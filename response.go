/*
{
  "id": "20190418_194301_00096_cf5ds",
  "infoUri": "http://localhost:8081/ui/query.html?20190418_194301_00096_cf5ds",
  "columns": [
    {
      "name": "_col0",
      "type": "integer",
      "typeSignature": {
        "rawType": "integer",
        "typeArguments": [],
        "literalArguments": [],
        "arguments": []
      }
    }
  ],
  "data": [
    [
      1
    ]
  ],
  "stats": {
    "state": "FINISHED",
    "queued": false,
    "scheduled": true,
    "nodes": 1,
    "totalSplits": 17,
    "queuedSplits": 0,
    "runningSplits": 0,
    "completedSplits": 17,
    "cpuTimeMillis": 3,
    "wallTimeMillis": 23,
    "queuedTimeMillis": 1,
    "elapsedTimeMillis": 38,
    "processedRows": 0,
    "processedBytes": 0,
    "peakMemoryBytes": 0,
    "spilledBytes": 0,
    "rootStage": {
      "stageId": "0",
      "state": "FINISHED",
      "done": true,
      "nodes": 1,
      "totalSplits": 17,
      "queuedSplits": 0,
      "runningSplits": 0,
      "completedSplits": 17,
      "cpuTimeMillis": 3,
      "wallTimeMillis": 23,
      "processedRows": 1,
      "processedBytes": 0,
      "subStages": []
    },
    "progressPercentage": 100
  },
  "warnings": [],
  "addedPreparedStatements": {},
  "deallocatedPreparedStatements": []
}
*/
package main

type TypeSignature struct {
	RawType          string        `json:"rawType"`
	TypeArguments    []interface{} `json:"typeArguments"`
	LiteralArguments []interface{} `json:"literalArguments"`
	Arguments        []interface{} `json:"arguments"`
}

type Column struct {
	Name          string        `json:"name"`
	Type          string        `json:"type"`
	TypeSignature TypeSignature `json:"typeSignature"`
}

type Stats struct {
	State              string      `json:"state"`
	Queued             bool        `json:"queued"`
	Scheduled          bool        `json:"scheduled"`
	ProgressPercentage interface{} `json:"progressPercentage"`
}

type Error struct {
	Message   string `json:"message"`
	ErrorCode int    `json:'errorCode"`
	ErrorName string `json:"errorName"`
	ErrorType string `json:"errorType"`
}

type Response struct {
	Id                            string          `json:"id"`
	InfoUri                       string          `json:"infoUri"`
	NextUri                       string          `json:"nextUri,omitempty"`
	Columns                       []*Column       `json:"columns,omitempty"`
	Data                          [][]interface{} `json:"data,omitempty"`
	Stats                         *Stats          `json:"stats"`
	Error                         *Error          `json:"error,omitempty"`
	Warnings                      []interface{}   `json:"warnings"`
	AddedPreparedStatements       struct{}        `json:"addedPreparedStatements"`
	DeallocatedPreparedStatements []interface{}   `json:"deallocatedPreparedStatements"`
}
