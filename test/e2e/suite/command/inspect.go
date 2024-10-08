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

package command

import (
	"path/filepath"

	. "github.com/notaryproject/notation/test/e2e/internal/notation"
	"github.com/notaryproject/notation/test/e2e/internal/utils"
	. "github.com/notaryproject/notation/test/e2e/suite/common"
	. "github.com/onsi/ginkgo/v2"
)

var (
	inspectSuccessfully = []string{
		"└── application/vnd.cncf.notary.signature",
		"└── sha256:",
		"├── media type:",
		"├── signature algorithm:",
		"├── signed attributes",
		"signingTime:",
		"signingScheme:",
		"├── user defined attributes",
		"│   └── (empty)",
		"├── unsigned attributes",
		"│   └── signingAgent: notation-go/",
		"├── certificates",
		"│   └── SHA256 fingerprint:",
		"issued to:",
		"issued by:",
		"expiry:",
		"└── signed artifact",
		"media type:",
		"digest:",
		"size:",
	}

	inspectSuccessfullyWithTimestamp = []string{
		"└── application/vnd.cncf.notary.signature",
		"└── sha256:",
		"├── media type:",
		"├── signature algorithm:",
		"├── signed attributes",
		"signingTime:",
		"signingScheme:",
		"├── user defined attributes",
		"│   └── (empty)",
		"├── unsigned attributes",
		"signingAgent: notation-go/",
		"timestamp signature",
		"timestamp:",
		"certificates",
		"SHA256 fingerprint:",
		"├── certificates",
		"│   └── SHA256 fingerprint:",
		"issued to:",
		"issued by:",
		"expiry:",
		"└── signed artifact",
		"media type:",
		"digest:",
		"size:",
	}
)

var _ = Describe("notation inspect", func() {
	It("all signatures of an image", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, artifact *Artifact, vhost *utils.VirtualHost) {
			notation.Exec("sign", artifact.ReferenceWithDigest()).
				MatchKeyWords(SignSuccessfully)

			notation.Exec("inspect", "-d", artifact.ReferenceWithDigest()).
				MatchKeyWords(inspectSuccessfully...)
		})
	})

	It("all signatures of an image with TLS", func() {
		HostInGithubAction(BaseOptions(), func(notation *utils.ExecOpts, artifact *Artifact, vhost *utils.VirtualHost) {
			notation.Exec("sign", artifact.DomainReferenceWithDigest()).
				MatchKeyWords(SignSuccessfully)

			notation.Exec("inspect", "-d", artifact.DomainReferenceWithDigest()).
				MatchKeyWords(inspectSuccessfully...).
				MatchErrKeyWords(HTTPSRequest).
				NoMatchErrKeyWords(HTTPRequest)
		})
	})

	It("all signatures of an image with --insecure-registry flag", func() {
		HostInGithubAction(BaseOptions(), func(notation *utils.ExecOpts, artifact *Artifact, vhost *utils.VirtualHost) {
			notation.Exec("sign", artifact.DomainReferenceWithDigest()).
				MatchKeyWords(SignSuccessfully)

			notation.Exec("inspect", "-d", "--insecure-registry", artifact.DomainReferenceWithDigest()).
				MatchKeyWords(inspectSuccessfully...).
				MatchErrKeyWords(HTTPRequest).
				NoMatchErrKeyWords(HTTPSRequest)
		})
	})

	It("sign with --force-referrers-tag set", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, artifact *Artifact, vhost *utils.VirtualHost) {
			notation.Exec("sign", "--force-referrers-tag", artifact.ReferenceWithDigest()).
				MatchKeyWords(SignSuccessfully)

			notation.Exec("inspect", artifact.ReferenceWithDigest(), "-v").
				MatchKeyWords(inspectSuccessfully...)
		})
	})

	It("sign with --force-referrers-tag set to false", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, artifact *Artifact, vhost *utils.VirtualHost) {
			notation.Exec("sign", "--force-referrers-tag=false", artifact.ReferenceWithDigest()).
				MatchKeyWords(SignSuccessfully)

			notation.Exec("inspect", artifact.ReferenceWithDigest(), "-v").
				MatchKeyWords(inspectSuccessfully...)
		})
	})

	It("sign with --allow-referrers-api set", func() {
		Host(BaseOptionsWithExperimental(), func(notation *utils.ExecOpts, artifact *Artifact, vhost *utils.VirtualHost) {
			notation.Exec("sign", "--allow-referrers-api", artifact.ReferenceWithDigest()).
				MatchKeyWords(SignSuccessfully)

			notation.Exec("inspect", artifact.ReferenceWithDigest(), "-v").
				MatchKeyWords(inspectSuccessfully...)

			notation.Exec("inspect", artifact.ReferenceWithDigest(), "--allow-referrers-api", "-v").
				MatchErrKeyWords(
					"Warning: This feature is experimental and may not be fully tested or completed and may be deprecated.",
					"Warning: flag '--allow-referrers-api' is deprecated and will be removed in future versions.",
				).
				MatchKeyWords(inspectSuccessfully...)
		})
	})

	It("sign with --allow-referrers-api set to false", func() {
		Host(BaseOptionsWithExperimental(), func(notation *utils.ExecOpts, artifact *Artifact, vhost *utils.VirtualHost) {
			notation.Exec("sign", "--allow-referrers-api=false", artifact.ReferenceWithDigest()).
				MatchKeyWords(SignSuccessfully)

			notation.Exec("inspect", artifact.ReferenceWithDigest(), "-v").
				MatchKeyWords(inspectSuccessfully...)

			notation.Exec("inspect", artifact.ReferenceWithDigest(), "--allow-referrers-api", "-v").
				MatchErrKeyWords(
					"Warning: This feature is experimental and may not be fully tested or completed and may be deprecated.",
					"Warning: flag '--allow-referrers-api' is deprecated and will be removed in future versions.",
				).
				MatchKeyWords(inspectSuccessfully...)
		})
	})

	It("with timestamping", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, artifact *Artifact, vhost *utils.VirtualHost) {
			notation.Exec("sign", "--timestamp-url", "http://rfc3161timestamp.globalsign.com/advanced", "--timestamp-root-cert", filepath.Join(NotationE2EConfigPath, "timestamp", "globalsignTSARoot.cer"), artifact.ReferenceWithDigest()).
				MatchKeyWords(SignSuccessfully)

			notation.Exec("inspect", artifact.ReferenceWithDigest()).
				MatchKeyWords(inspectSuccessfullyWithTimestamp...)
		})
	})
})
