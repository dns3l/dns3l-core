// Mainly to launch + control a StepCA instance for testing
package step

import (
	"bufio"
	"errors"
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

type StepCAController struct {
	cmd  *exec.Cmd
	Port int
}

func getStepDataBasedir() string {
	return filepath.Join(util.GetExecDir(), "testdata", "step")
}

func (c *StepCAController) Start() error {
	return c.startRaw(false)

}

func (c *StepCAController) startRaw(mustExist bool) error {

	caExisted := true
	if !c.CAExists() {
		if mustExist {
			return errors.New("CA does not exist, but shall not create it")
		}
		err := c.CreateCA()
		if err != nil {
			return err
		}
		caExisted = false
	}

	c.cmd = exec.Command("step-ca",
		fmt.Sprintf("--password-file=%s", c.getPwdFile()))

	c.cmd.Env = c.envs()

	stdoutr, _ := c.cmd.StdoutPipe()
	stderrr, _ := c.cmd.StderrPipe()

	ready := make(chan error)

	c.startScanForReadyLine(stdoutr, ready, "stdout")
	c.startScanForReadyLine(stderrr, ready, "stderr")

	err := c.cmd.Start()
	if err != nil {
		return err
	}

	log.Info("Waiting for StepCA to start up...")

	err = <-ready
	if err != nil {
		return err
	}

	log.Info("StepCA successfully started up. Adding ACME module...")

	if !caExisted {
		err := c.addACMEModule()
		if err != nil {
			return err
		}
		//Must restart StepCA for the module to load
		err = c.Stop()
		if err != nil {
			return err
		}
		c.cmd = nil
		err = c.startRaw(true)
		if err != nil {
			return err
		}
	}

	return nil

}

var scaready = regexp.MustCompile(`Serving HTTPS`)

func (c *StepCAController) startScanForReadyLine(r io.Reader, ready chan error, stream string) {

	scanner := bufio.NewScanner(r)

	go func() {
		hasbeenready := false
		for scanner.Scan() {
			line := scanner.Text()
			if scaready.FindStringIndex(line) != nil {
				ready <- nil
				hasbeenready = true
			}
			log.WithField("stream", stream).Debugf("StepCA: %s", line)
		}
		if c.cmd == nil {
			log.Debugf("StepCA: cmd is already null, terminating stream.")
			return
		}
		err := c.cmd.Wait()
		if err != nil {
			ready <- err
		} else {
			rc := c.cmd.ProcessState.ExitCode()
			if !hasbeenready {
				ready <- fmt.Errorf("StepCA exited before being ready for connections, rc=%d", rc)
			} else {
				log.Warnf("StepCA exited, rc=%d", rc)
			}
		}
	}()

}

func (c *StepCAController) Stop() error {
	err := c.cmd.Process.Signal(syscall.SIGTERM)
	if err != nil {
		return err
	}
	err = c.cmd.Wait()
	if err != nil {
		if err, ok := err.(*exec.ExitError); ok {
			log.Warnf("StepCA exited with non-null after sigterm, rc=%d", err.ExitCode())
			return nil
		}
		if err, ok := err.(*os.SyscallError); ok {
			if strings.HasSuffix(err.Error(), "no child processes") {
				//this seems to mean that stepca process is already closed
				return nil
			}

		}
		return err
	}
	return nil
}

func (c *StepCAController) CAExists() bool {
	_, err := os.Stat(filepath.Join(getStepDataBasedir(), "config", "defaults.json")) //TODO find out what is created here
	return err == nil
}

func (c *StepCAController) envs() []string {
	res := os.Environ()
	res = append(res, fmt.Sprintf("STEPPATH=%s", getStepDataBasedir()))
	return res
}

func (c *StepCAController) getPwdFile() string {
	return filepath.Join(getStepDataBasedir(), "steppwd")
}

const steppwd = "bogus"

func (c *StepCAController) CreateCA() error {

	err := os.MkdirAll(getStepDataBasedir(), 0755)
	if err != nil {
		return err
	}

	pwbytes := []byte(steppwd)
	err = os.WriteFile(c.getPwdFile(), pwbytes, 0600)
	if err != nil {
		return err
	}

	createcmd := exec.Command("step", []string{
		"ca", "init",
		"--deployment-type=standalone",
		"--name=test",
		"--dns=localhost",
		fmt.Sprintf("--address=127.0.0.1:%d", c.Port),
		fmt.Sprintf("--password-file=%s", c.getPwdFile()),
		"--provisioner=test",
	}...)
	createcmd.Env = c.envs()

	createcmd.Stdout = os.Stdout
	createcmd.Stderr = os.Stderr

	err = createcmd.Start()
	if err != nil {
		return err
	}

	err = createcmd.Wait()
	if err != nil {
		if err, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("DB create exited with non-0, rc=%d",
				err.ExitCode())
		}
		return err
	}

	return nil

}

func (c *StepCAController) addACMEModule() error {

	addacmecmd := exec.Command("step", []string{
		"ca", "provisioner", "add", "acme",
		"--type=ACME",
		fmt.Sprintf("--ca-url=https://localhost:%d", c.Port),
	}...)

	addacmecmd.Env = c.envs()

	out := strings.Builder{}

	addacmecmd.Stdout = &out
	addacmecmd.Stderr = &out

	err := addacmecmd.Run()
	if err != nil {
		log.Errorf("Add ACME module cmd returned error '%s'", out.String())
		return fmt.Errorf("step CA: Add ACME provisioner command exited with non-0: %w", err)
	} else {
		log.Debugf("Add ACME module cmd returned '%s'", out.String())
	}

	return nil

}
