package logger

import (
	"time"
)

// LogBodyMaxSize is the max size in bytes
const LogBodyMaxSize = 4096

// ExternalRequestFieldsBuilder external request log data (fields) builder
type ExternalRequestFieldsBuilder interface {
	// GetFields returns log data for external requests
	// complies with Pandora log standards
	GetFields() map[string]interface{}
	// Reset resets previously set data
	Reset() ExternalRequestFieldsBuilder
	// SetApplication set a target application name for an external request
	SetApplication(name string) ExternalRequestFieldsBuilder
	// SetTime set time when a request to external service was triggered
	SetTime(time time.Time) ExternalRequestFieldsBuilder
	// SetStatusCode set a response status code returned from external service
	SetStatusCode(statusCode int) ExternalRequestFieldsBuilder
	// SetRequestMethod set a request method of performing request
	SetRequestMethod(method string) ExternalRequestFieldsBuilder
	// SetURL set url
	SetURL(url string) ExternalRequestFieldsBuilder
	// SetRespDuration set a duration of remote call
	SetRespDuration(duration time.Duration) ExternalRequestFieldsBuilder
	// SetRequestBody set a request body of performing remote call
	SetRequestBody(body string) ExternalRequestFieldsBuilder
	// SetResponseBody set a response body returned from external service
	SetResponseBody(body string) ExternalRequestFieldsBuilder
}

// extReqData implements ExternalRequestFieldsBuilder
var _ ExternalRequestFieldsBuilder = (*extReqData)(nil)

// extReqData is a struct that contains the fields to be logged for external request
type extReqData struct {
	fields map[string]interface{}
}

// NewExternalRequestFieldsBuilder construct for extReqData
func NewExternalRequestFieldsBuilder() ExternalRequestFieldsBuilder {
	return &extReqData{
		fields: make(map[string]interface{}),
	}
}

// GetFields returns log data for external requests
func (d *extReqData) GetFields() map[string]interface{} {
	return d.fields
}

// Reset resets previously set data
func (d *extReqData) Reset() ExternalRequestFieldsBuilder {
	d.fields = make(map[string]interface{})
	return d
}

// SetApplication set a target application name for an external request
func (d *extReqData) SetApplication(name string) ExternalRequestFieldsBuilder {
	d.fields["application"] = name
	return d
}

// SetTime set time when a request to external service was triggered
func (d *extReqData) SetTime(time time.Time) ExternalRequestFieldsBuilder {
	d.fields["time"] = time.Format(TimestampFormat)
	return d
}

// SetStatusCode set a response status code returned from external service
func (d *extReqData) SetStatusCode(statusCode int) ExternalRequestFieldsBuilder {
	d.fields["response.status_code"] = statusCode
	return d
}

// SetRequestMethod set a request method of performing request
func (d *extReqData) SetRequestMethod(method string) ExternalRequestFieldsBuilder {
	d.fields["method"] = method
	return d
}

// SetURL set url
func (d *extReqData) SetURL(url string) ExternalRequestFieldsBuilder {
	d.fields["url"] = url
	return d
}

// SetRespDuration set a duration of remote call
func (d *extReqData) SetRespDuration(duration time.Duration) ExternalRequestFieldsBuilder {
	d.fields["response.time_ms"] = duration.Milliseconds()
	return d
}

// SetRequestBody set a request body of performing remote call
func (d *extReqData) SetRequestBody(body string) ExternalRequestFieldsBuilder {
	maxSize := LogBodyMaxSize
	if len(body) < maxSize {
		maxSize = len(body)
	}
	d.fields["payload"] = body[:maxSize]
	return d
}

// SetResponseBody set a response body returned from external service
func (d *extReqData) SetResponseBody(body string) ExternalRequestFieldsBuilder {
	maxSize := LogBodyMaxSize
	if len(body) < maxSize {
		maxSize = len(body)
	}
	d.fields["response.body"] = body[:maxSize]
	return d
}
