/*
Copyright © 2020 NAME HERE dreddick.home@gmail.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	cr "github.com/dreddick-home/certrenew/pkg/kcertrenew"
	"github.com/spf13/cobra"
)

// renewCmd represents the renew command
var renewCmd = &cobra.Command{
	Use:   "renew",
	Short: "Renew the public cert in a kubeconfig file.",
	Long: `Command to renew the public cert for a user in a kubeconfig file.

The public cert data is stored base64 encoded in the users[].user.client-certificate-data field.

A filesystem root can be set and the command expects the root ca key and cert to be available under the root at /etc/kubernetes/pki 

This command will renew the client cert for a named kubeconfig file and store the new config in a new location.`,
	Run: func(cmd *cobra.Command, args []string) {
		kubeconfig, _ := cmd.Flags().GetString("kubeconfig")
		expire, _ := cmd.Flags().GetInt("expire")
		caKey, _ := cmd.Flags().GetString("ca-key")
		caCert, _ := cmd.Flags().GetString("ca-cert")
		outputdir, _ := cmd.Flags().GetString("outputdir")
		cr.RenewKubeconfig(kubeconfig, caKey, caCert, outputdir, expire)
	},
}

func init() {
	rootCmd.AddCommand(renewCmd)

	renewCmd.Flags().String("kubeconfig", "", "The path to the kubeconfig file to renew certs in (required)")
	renewCmd.MarkFlagRequired("kubeconfig")
	renewCmd.Flags().String("outputdir", ".", "The name of the output directory to write config to.")
	renewCmd.Flags().String("ca-cert", "", "The path to the ca cert file. (required)")
	renewCmd.MarkFlagRequired("ca-cert")
	renewCmd.Flags().String("ca-key", "", "The path to the ca key file. (required)")
	renewCmd.MarkFlagRequired("ca-key")
	renewCmd.Flags().Int("expire", 12, "The number of months to set the certificate to expire in")
}
