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
	"fmt"
	"net/http"
)

// Q contains options for querying a set of records in the database.
type Q struct {
	Count        int               `json:"count,omitempty"`
	IncludeData  bool              `json:"include_data,omitempty"`
	WriterIDs    []string          `json:"writer_ids,omitempty"`
	UserIDs      []string          `json:"user_ids,omitempty"`
	RecordIDs    []string          `json:"record_ids,omitempty"`
	ContentTypes []string          `json:"content_types,omitempty"`
	AfterIndex   int               `json:"after_index,omitempty"`
	Plain        map[string]string `json:"plain,omitempty"`
}

type searchRecord struct {
	Meta Meta              `json:"meta"`
	Data map[string]string `json:"record_data"`
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
	err      error           // last error to report
}

// Next advances the cursor to the next position (if available), and
// return true if the cursor is at a valid item.
func (c *Cursor) Next() bool {
	// Stop iteration once we've hit an error.
	if c.err != nil {
		return false
	}

	var err error

	// If there is no response, or we've read all its results, perform
	// the next search query.
	if c.response == nil || c.index+1 >= len(c.response.Results) {
		if c.response != nil {
			c.query.AfterIndex = c.response.LastIndex
		}

		c.response, err = c.client.search(c.ctx, c.query)
		if err != nil {
			c.err = err
			return false
		}

		if len(c.response.Results) == 0 {
			return false
		}

		c.index = 0
	} else {
		c.index++
	}

	return true
}

// Get returns the record at the current cursor position.
func (c *Cursor) Get() (*Record, error) {
	if c.err != nil {
		return nil, c.err
	}

	record := c.response.Results[c.index].toRecord()
	if c.query.IncludeData {
		err := c.client.decryptRecord(c.ctx, record)
		if err != nil {
			c.err = err
			return nil, err
		}
	}

	return record, nil
}

// Query executes a database query given a set of search parameters,
// returning a cursor that can be iterated over to loop through
// the result set.
func (c *Client) Query(ctx context.Context, q Q) *Cursor {
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

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/search", c.apiURL()), &buf)
	if err != nil {
		return nil, err
	}

	var result searchResponse
	resp, err := c.rawCall(ctx, req, &result)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	return &result, nil
}
