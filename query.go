//
// query.go --- Querying records.
//
// Copyright (C) 2017, Tozny, LLC.
// All Rights Reserved.
//

package e3db

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// Q contains options for querying a set of records in the database.
type Q struct {
	Count        int               `json:"count"`
	IncludeData  bool              `json:"include_data,omitempty"`
	WriterIDs    []string          `json:"writer_ids,omitempty"`
	UserIDs      []string          `json:"user_ids,omitempty"`
	RecordIDs    []string          `json:"record_ids,omitempty"`
	ContentTypes []string          `json:"content_types,omitempty"`
	AfterIndex   int               `json:"after_index,omitempty"`
	Plain        map[string]string `json:"plain,omitempty"`
}

type searchRecord struct {
	Meta      Meta              `json:"meta"`
	Data      map[string]string `json:"record_data"`
	AccessKey *getEAKResponse   `json:"access_key"`
}

func (r *searchRecord) toRecord() *Record {
	rec := Record{Meta: r.Meta}
	if r.Data != nil {
		rec.Data = r.Data
	} else {
		rec.Data = make(map[string]string)
	}

	return &rec
}

type searchResponse struct {
	Results   []searchRecord `json:"results"`
	LastIndex int            `json:"last_index"`
}

// Cursor represents an iterator into a recordset returned by 'e3db.Query'.
type Cursor struct {
	query    Q               // current query
	response *searchResponse // last response
	client   *Client         // e3db client object
	ctx      context.Context // execution context
	index    int             // current position in 'response'
}

// Done is returned by Next when iteration is complete.
var Done = errors.New("iteration complete")

// Next returns the item at the current iterator position (if one is
// available).
func (c *Cursor) Next() (*Record, error) {
	var err error

	// If there is no response, or we've read all its results, perform
	// the next search query.
	if c.response == nil || c.index+1 >= len(c.response.Results) {
		if c.response != nil {
			c.query.AfterIndex = c.response.LastIndex

			// If the previous response was shorter than a full page,
			// we know we've reached the end of the result set.
			if len(c.response.Results) < c.query.Count {
				return nil, Done
			}
		}

		c.response, err = c.client.search(c.ctx, c.query)
		if err != nil {
			return nil, err
		}

		if len(c.response.Results) == 0 {
			return nil, Done
		}

		c.index = 0
	} else {
		c.index++
	}

	record := c.response.Results[c.index].toRecord()
	if c.query.IncludeData {
		accessKey := c.response.Results[c.index].AccessKey
		var err error

		if accessKey != nil {
			ak, err := c.client.decryptEAK(accessKey)
			if err != nil {
				return nil, err
			}
			err = c.client.decryptRecordWithKey(record, ak)
		} else {
			err = c.client.decryptRecord(c.ctx, record)
		}

		if err != nil {
			return nil, err
		}
	}

	return record, nil
}

// Query executes a database query given a set of search parameters,
// returning a cursor that can be iterated over to loop through
// the result set.
func (c *Client) Query(ctx context.Context, q Q) *Cursor {
	if q.Count == 0 {
		q.Count = 50
	}

	return &Cursor{
		client:   c,
		ctx:      ctx,
		index:    0,
		query:    q,
		response: nil,
	}
}

// TODO: This should be some kind of generator-style interface that
// fetches a block of records at a time.
func (c *Client) search(ctx context.Context, q Q) (*searchResponse, error) {
	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(&q)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/v1/storage/search", c.apiURL()), &buf)
	if err != nil {
		return nil, err
	}

	var result searchResponse
	resp, err := c.rawCall(ctx, req, &result)
	if err != nil {
		return nil, err
	}

	defer closeResp(resp)
	return &result, nil
}
