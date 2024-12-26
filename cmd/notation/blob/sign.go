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

package blob

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/notaryproject/notation-core-go/revocation/purpose"
	corex509 "github.com/notaryproject/notation-core-go/x509"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/log"
	"github.com/notaryproject/notation/cmd/notation/internal/cmdutil"
	"github.com/notaryproject/notation/internal/cmd"
	"github.com/notaryproject/notation/internal/envelope"
	"github.com/notaryproject/notation/internal/httputil"
	"github.com/notaryproject/notation/internal/osutil"
	clirev "github.com/notaryproject/notation/internal/revocation"
	nx509 "github.com/notaryproject/notation/internal/x509"
	"github.com/notaryproject/tspclient-go"
	"github.com/spf13/cobra"
)

// timestampingTimeout is the timeout when requesting timestamp countersignature
// from a TSA
const timestampingTimeout = 15 * time.Second

type blobSignOpts struct {
	cmd.LoggingFlagOpts
	cmd.SignerFlagOpts
	expiry                 time.Duration
	pluginConfig           []string
	userMetadata           []string
	blobPath               string
	blobMediaType          string
	signatureDirectory     string
	tsaServerURL           string
	tsaRootCertificatePath string
	force                  bool
}

func signCommand(opts *blobSignOpts) *cobra.Command {
	if opts == nil {
		opts = &blobSignOpts{}
	}
	longMessage := `Produce a detached signature for a given blob.

The signature file will be written to the currently working directory with file name "{blob file name}.{signature format}.sig".

Note: a signing key must be specified. This can be done temporarily by specifying a key ID, or a new key can be configured using the command "notation key add"

Example - Sign a blob artifact using the default signing key, with the default JWS envelope, and store the signature at current directory:
  notation blob sign <blob_path>

Example - Sign a blob artifact by generating the signature in a particular directory: 
  notation blob sign --signature-directory <directory_path> <blob_path>

Example - Sign a blob artifact and skip user confirmations when overwriting existing signature:
  notation blob sign --force <blob_path> 

Example - Sign a blob artifact using the default signing key, with the COSE envelope:
  notation blob sign --signature-format cose <blob_path>

Example - Sign a blob artifact with a specified plugin and signing key stored in KMS: 
  notation blob sign --plugin <plugin_name> --id <remote_key_id> <blob_path>

Example - Sign a blob artifact and add a user metadata to payload: 
  notation blob sign --user-metadata <metadata> <blob_path>

Example - Sign a blob artifact using a specified media type: 
  notation blob sign --media-type <media type> <blob_path>

Example - Sign a blob artifact using a specified key: 
  notation blob sign --key <key_name> <blob_path>

Example - Sign a blob artifact and specify the signature expiry duration, for example 24 hours: 
  notation blob sign --expiry 24h <blob_path>

Example - Sign a blob artifact with timestamping:
  notation blob sign --timestamp-url <TSA_url> --timestamp-root-cert <TSA_root_certificate_filepath> <registry>/<repository>@<digest> 
`

	command := &cobra.Command{
		Use:   "sign [flags] <blobPath>",
		Short: "Sign blob artifacts",
		Long:  longMessage,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("missing file path to the blob artifact: use `notation blob sign --help` to see what parameters are required")
			}
			opts.blobPath = args[0]
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// timestamping
			if cmd.Flags().Changed("timestamp-url") {
				if opts.tsaServerURL == "" {
					return errors.New("timestamping: tsa url cannot be empty")
				}
				if opts.tsaRootCertificatePath == "" {
					return errors.New("timestamping: tsa root certificate path cannot be empty")
				}
			}
			return runBlobSign(cmd, opts)
		},
	}
	opts.LoggingFlagOpts.ApplyFlags(command.Flags())
	opts.SignerFlagOpts.ApplyFlagsToCommand(command)
	cmd.SetPflagExpiry(command.Flags(), &opts.expiry)
	cmd.SetPflagPluginConfig(command.Flags(), &opts.pluginConfig)
	cmd.SetPflagUserMetadata(command.Flags(), &opts.userMetadata, cmd.PflagUserMetadataSignUsage)
	command.Flags().StringVar(&opts.blobMediaType, "media-type", "application/octet-stream", "media type of the blob")
	command.Flags().StringVar(&opts.signatureDirectory, "signature-directory", ".", "directory where the blob signature needs to be placed")
	command.Flags().StringVar(&opts.tsaServerURL, "timestamp-url", "", "RFC 3161 Timestamping Authority (TSA) server URL")
	command.Flags().StringVar(&opts.tsaRootCertificatePath, "timestamp-root-cert", "", "filepath of timestamp authority root certificate")
	command.Flags().BoolVar(&opts.force, "force", false, "override the existing signature file, never prompt")
	command.MarkFlagsRequiredTogether("timestamp-url", "timestamp-root-cert")
	return command
}

func runBlobSign(command *cobra.Command, cmdOpts *blobSignOpts) error {
	// set log level
	ctx := cmdOpts.LoggingFlagOpts.InitializeLogger(command.Context())

	signer, err := cmd.GetBlobSigner(ctx, &cmdOpts.SignerFlagOpts)
	if err != nil {
		return err
	}
	blobOpts, err := prepareBlobSigningOpts(ctx, cmdOpts)
	if err != nil {
		return err
	}
	blobFile, err := os.Open(cmdOpts.blobPath)
	if err != nil {
		return err
	}
	defer blobFile.Close()

	// core process
	sig, _, err := notation.SignBlob(ctx, signer, blobFile, blobOpts)
	if err != nil {
		return err
	}
	signaturePath := signatureFilepath(cmdOpts.signatureDirectory, cmdOpts.blobPath, cmdOpts.SignatureFormat)
	fmt.Printf("Writing signature to file %q...\n", signaturePath)

	// optional confirmation
	if !cmdOpts.force {
		if _, err := os.Stat(signaturePath); err == nil {
			confirmed, err := cmdutil.AskForConfirmation(os.Stdin, "The signature file already exists, do you want to overwrite it?", cmdOpts.force)
			if err != nil {
				return err
			}
			if !confirmed {
				return nil
			}
		}
	} else {
		fmt.Fprintln(os.Stderr, "Warning: existing signature file will be overwritten")
	}

	// write signature to file
	if err := osutil.WriteFile(signaturePath, sig); err != nil {
		return fmt.Errorf("failed to write signature to file: %w", err)
	}
	fmt.Printf("Successfully signed %q\n ", cmdOpts.blobPath)
	fmt.Printf("Signature file written to %q\n", signaturePath)
	return nil
}

func prepareBlobSigningOpts(ctx context.Context, opts *blobSignOpts) (notation.SignBlobOptions, error) {
	logger := log.GetLogger(ctx)

	mediaType, err := envelope.GetEnvelopeMediaType(opts.SignerFlagOpts.SignatureFormat)
	if err != nil {
		return notation.SignBlobOptions{}, err
	}
	pluginConfig, err := cmd.ParseFlagMap(opts.pluginConfig, cmd.PflagPluginConfig.Name)
	if err != nil {
		return notation.SignBlobOptions{}, err
	}
	userMetadata, err := cmd.ParseFlagMap(opts.userMetadata, cmd.PflagUserMetadata.Name)
	if err != nil {
		return notation.SignBlobOptions{}, err
	}
	signBlobOpts := notation.SignBlobOptions{
		SignerSignOptions: notation.SignerSignOptions{
			SignatureMediaType: mediaType,
			ExpiryDuration:     opts.expiry,
			PluginConfig:       pluginConfig,
		},
		ContentMediaType: opts.blobMediaType,
		UserMetadata:     userMetadata,
	}
	if opts.tsaServerURL != "" {
		// timestamping
		logger.Infof("Configured to timestamp with TSA %q", opts.tsaServerURL)
		signBlobOpts.Timestamper, err = tspclient.NewHTTPTimestamper(httputil.NewClient(ctx, &http.Client{Timeout: timestampingTimeout}), opts.tsaServerURL)
		if err != nil {
			return notation.SignBlobOptions{}, fmt.Errorf("cannot get http timestamper for timestamping: %w", err)
		}

		rootCerts, err := corex509.ReadCertificateFile(opts.tsaRootCertificatePath)
		if err != nil {
			return notation.SignBlobOptions{}, err
		}
		if len(rootCerts) == 0 {
			return notation.SignBlobOptions{}, fmt.Errorf("cannot find any certificate from %q. Expecting single x509 root certificate in PEM or DER format from the file", opts.tsaRootCertificatePath)
		}
		if len(rootCerts) > 1 {
			return notation.SignBlobOptions{}, fmt.Errorf("found more than one certificates from %q. Expecting single x509 root certificate in PEM or DER format from the file", opts.tsaRootCertificatePath)
		}
		tsaRootCert := rootCerts[0]
		isRoot, err := nx509.IsRootCertificate(tsaRootCert)
		if err != nil {
			return notation.SignBlobOptions{}, fmt.Errorf("failed to check root certificate with error: %w", err)
		}
		if !isRoot {
			return notation.SignBlobOptions{}, fmt.Errorf("certificate from %q is not a root certificate. Expecting single x509 root certificate in PEM or DER format from the file", opts.tsaRootCertificatePath)

		}
		rootCAs := x509.NewCertPool()
		rootCAs.AddCert(tsaRootCert)
		signBlobOpts.TSARootCAs = rootCAs
		tsaRevocationValidator, err := clirev.NewRevocationValidator(ctx, purpose.Timestamping)
		if err != nil {
			return notation.SignBlobOptions{}, fmt.Errorf("failed to create timestamping revocation validator: %w", err)
		}
		signBlobOpts.TSARevocationValidator = tsaRevocationValidator
	}
	return signBlobOpts, nil
}

// signatureFilepath returns the path to the signature file.
func signatureFilepath(signatureDirectory, blobPath, signatureFormat string) string {
	blobFilename := filepath.Base(blobPath)
	signatureFilename := fmt.Sprintf("%s.%s.sig", blobFilename, signatureFormat)
	return filepath.Join(signatureDirectory, signatureFilename)
}