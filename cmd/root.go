package cmd

import (
	"sync"

	"github.com/LINKMobilityDE/ns-checker/checker"
	"github.com/LINKMobilityDE/ns-checker/zones"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var (
	dirs   []string
	chkr   *checker.Checker
	chkrMU sync.RWMutex
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "ns-checker",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	RunE: runRoot,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		err := cmd.MarkPersistentFlagRequired("dir")
		if err != nil {
			return err
		}
		return cmd.MarkPersistentFlagDirname("dir")
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	pf := rootCmd.PersistentFlags()
	pf.StringArrayVarP(&dirs, "dir", "d", nil, "directories with zone files to parse")
	cobra.MarkFlagRequired(pf, "dir")
}

func runRoot(cmd *cobra.Command, args []string) error {
	err := updateChecker()
	if err != nil {
		return err
	}
	checks := map[string][]dns.RR{}
	if checks["a"], err = chkr.CheckA(); err != nil {
		return err
	}
	if checks["aaaa"], err = chkr.CheckAAAA(); err != nil {
		return err
	}
	if checks["ptr"], err = chkr.CheckPTR(); err != nil {
		return err
	}
	for name, fails := range checks {
		if len(fails) > 0 {
			cmd.Printf("Failed %s records:\n%v\n", name, checker.FormatFailed(fails, "\n"))
		}
	}
	return nil
}

func updateChecker() error {
	rr := new(zones.Records)
	for _, dir := range dirs {
		other, err := zones.ParseDirectory(dir)
		if err != nil {
			return err
		}
		rr.Merge(other)
	}
	chkrMU.Lock()
	chkr = &checker.Checker{Records: rr}
	chkrMU.Unlock()
	return nil
}
