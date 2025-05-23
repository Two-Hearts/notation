// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package json

import (
	coresignature "github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation/v2/cmd/notation/internal/display/output"
)

// BlobInspectHandler is a handler for inspecting metadata information and
// rendering it in JSON format. It implements the metadata.BlobInspectHandler
// interface.
type BlobInspectHandler struct {
	printer   *output.Printer
	signature *signature
}

// NewBlobInspectHandler creates a BlobInspectHandler to inspect signature and
// print in JSON format.
func NewBlobInspectHandler(printer *output.Printer) *BlobInspectHandler {
	return &BlobInspectHandler{
		printer: printer,
	}
}

// OnEnvelopeParsed sets the parsed envelope for the handler.
func (h *BlobInspectHandler) OnEnvelopeParsed(nodeName, signatureMediaType string, envelope coresignature.Envelope) error {
	// blob signature does not have a digest
	sig, err := newSignature("", signatureMediaType, envelope)
	if err != nil {
		return err
	}
	h.signature = sig
	return nil
}

// Render prints out the metadata information in JSON format.
func (h *BlobInspectHandler) Render() error {
	return output.PrintPrettyJSON(h.printer, h.signature)
}
