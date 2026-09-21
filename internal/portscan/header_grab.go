package portscan

import (
	"bufio"
	"net/textproto"
)

func grabHeaders(
	reader *bufio.Reader,
) map[string][]string {
	headers := make(
		map[string][]string,
	)

	tp := textproto.NewReader(
		reader,
	)

	mimeHeaders, err :=
		tp.ReadMIMEHeader()

	if err != nil {
		return headers
	}

	for name, values := range mimeHeaders {

		headers[name] = append(
			[]string(nil),
			values...,
		)
	}

	return headers
}
