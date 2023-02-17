// Mainly to launch + control a MariaDB instance for testing
package mariadb

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/dns3l/dns3l-core/util"
)

type MariaDBController struct {
	cmd  *exec.Cmd
	Port int
}

func getDBDataBasedir() string {
	return filepath.Join(util.GetExecDir(), "testdata")
}

func (c *MariaDBController) getMariaDBArgs() []string {
	return []string{
		"--datadir", filepath.Join(getDBDataBasedir(), "db"),
		"--socket", filepath.Join(getDBDataBasedir(), "db.sock"),
		"--pid-file", filepath.Join(getDBDataBasedir(), "db.pid"),
		"--port", fmt.Sprint(c.Port),
	}

}

func (c *MariaDBController) Start() error {

	if !c.DatabaseExists() {
		err := c.CreateDB()
		if err != nil {
			return err
		}
	}

	c.cmd = exec.Command("mariadbd", c.getMariaDBArgs()...)

	stdoutr, _ := c.cmd.StdoutPipe()
	stderrr, _ := c.cmd.StderrPipe()

	ready := make(chan error)

	c.startScanForReadyLine(stdoutr, ready, "stdout")
	c.startScanForReadyLine(stderrr, ready, "stderr")

	err := c.cmd.Start()
	if err != nil {
		return err
	}

	log.Info("Waiting for mariadb to start up...")

	err = <-ready
	if err != nil {
		return err
	}

	log.Info("MariaDB successfully started up. Continuing...")

	return nil

}

var mdbready = regexp.MustCompile(`ready for connections.$`)

func (c *MariaDBController) startScanForReadyLine(r io.Reader, ready chan error, stream string) {

	scanner := bufio.NewScanner(r)

	go func() {
		hasbeenready := false
		for scanner.Scan() {
			line := scanner.Text()
			if mdbready.FindStringIndex(line) != nil {
				ready <- nil
				hasbeenready = true
			}
			log.WithField("stream", stream).Debugf("mariadb: %s", line)
		}
		err := c.cmd.Wait()
		if err != nil {
			ready <- err
		} else {
			rc := c.cmd.ProcessState.ExitCode()
			if !hasbeenready {
				ready <- fmt.Errorf("mariadb exited before being ready for connections, rc=%d", rc)
			} else {
				log.Warnf("MariaDB exited, rc=%d", rc)
			}
		}
	}()

}

func (c *MariaDBController) Stop() error {
	err := c.cmd.Process.Signal(syscall.SIGTERM)
	if err != nil {
		return err
	}
	err = c.cmd.Wait()
	if err != nil {
		if err, ok := err.(*exec.ExitError); ok {
			log.Warnf("MariaDB exited with non-null after sigterm, rc=%d", err.ExitCode())
			return nil
		}
		if err, ok := err.(*os.SyscallError); ok {
			if strings.HasSuffix(err.Error(), "no child processes") {
				//this seems to mean that db process is already closed
				return nil
			}

		}
		return err
	}
	return nil
}

func (c *MariaDBController) DatabaseExists() bool {
	_, err := os.Stat(filepath.Join(util.GetExecDir(), "db", "ibdata1"))
	return err == nil
}

func (c *MariaDBController) CreateDB() error {

	err := os.MkdirAll(filepath.Join(getDBDataBasedir(), "db"), 0755)
	if err != nil {
		return err
	}

	createcmd := exec.Command("mariadb-install-db", []string{
		"--verbose",
		"--datadir", filepath.Join(getDBDataBasedir(), "db"),
	}...)

	createcmd.Stdout = os.Stdout
	createcmd.Stderr = os.Stderr

	err = createcmd.Start()
	if err != nil {
		return err
	}

	err = createcmd.Wait()
	if err != nil {
		if err, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("DB create exited with non-null, rc=%d",
				err.ExitCode())
		}
		return err
	}

	return nil

}
