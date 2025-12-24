// pkg/app/setup.go
package app

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"revealr/pkg/output" // For consistent output formatting
)

// RunSetup performs checks for required tools and attempts to fulfill them.
func RunSetup() {
	output.PrintInfo("Starting Revealr Setup Wizard...")
	output.PrintInfo("This process will check for and help install/configure necessary tools.")
	output.PrintInfo("Administrator privileges may be required for some steps.")
	fmt.Println()

	var (
		cmd *exec.Cmd
		err error

		pythonPath       string
		pythonFound      bool
		venvPath         string = "./venv"
		pipPath          string
		venvActivated    bool
		generateProtoBat string

		dbFile string = "data/db/revealr.db"
		reader *bufio.Reader
		input  string

		failureMessages []string
	)

	recordFailure := func(msg string) {
		output.PrintError(msg)
		failureMessages = append(failureMessages, msg)
	}

	output.PrintInfo("Checking Go installation...")
	if !checkCommand("go", "--version") {
		recordFailure("Go not found. Please install Go from https://go.dev/dl/ and ensure it's in your system PATH. (Essential for building Revealr from source).")
	} else {
		output.PrintSuccess("Go found.")
	}
	fmt.Println()

	output.PrintInfo("Checking Git installation...")
	if !checkCommand("git", "--version") {
		recordFailure("Git not found. Please install Git from https://git-scm.com/downloads and ensure it's in your system PATH. (Required for building Revealr).")
	} else {
		output.PrintSuccess("Git found.")
	}
	fmt.Println()

	output.PrintInfo("Checking Protoc (Protocol Buffers Compiler) installation...")
	if !checkCommand("protoc", "--version") {
		recordFailure("Protoc not found. Download from https://github.com/protocolbuffers/protobuf/releases (protoc-*-win64.zip for Windows) and add its 'bin' directory to your system PATH. (Required for protobuf generation).")
	} else {
		output.PrintSuccess("Protoc found.")
	}
	fmt.Println()

	output.PrintInfo("Checking Python and Virtual Environment setup...")
	pythonPath, pythonFound = checkPython()
	if !pythonFound {
		recordFailure("Python 3.x not found. Please install from https://www.python.org/downloads/. (Required for Revealr's intelligence engine).")
	} else {
		output.PrintSuccess("Python found: %s", pythonPath)

		if _, err = os.Stat(venvPath); os.IsNotExist(err) {
			output.PrintInfo("Python virtual environment not found. Creating one...")
			cmd = exec.Command(pythonPath, "-m", "venv", "venv")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err = cmd.Run(); err != nil {
				recordFailure(fmt.Sprintf("Failed to create virtual environment: %v", err))
			} else {
				output.PrintSuccess("Virtual environment created.")
			}
		} else {
			output.PrintSuccess("Virtual environment already exists.")
		}

		if pythonFound && (err == nil || !strings.Contains(err.Error(), "venv")) {
			output.PrintInfo("Installing/Updating Python libraries (grpcio-tools, requests) in virtual environment...")
			pipPath = fmt.Sprintf("%s/Scripts/pip.exe", venvPath)
			if runtime.GOOS != "windows" {
				pipPath = fmt.Sprintf("%s/bin/pip", venvPath)
			}

			// The pipPath variable is used below, so it's not "unused"
			pipPath = fmt.Sprintf(`call "%s\activate.bat" && pip install --upgrade grpcio grpcio-tools requests`, venvPath)
			if runtime.GOOS != "windows" {
				pipPath = fmt.Sprintf(`source "%s/bin/activate" && pip install --upgrade grpcio grpcio-tools requests`, venvPath)
				cmd = exec.Command("bash", "-c", pipPath)
			} else {
				cmd = exec.Command("cmd", "/c", pipPath)
			}

			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err = cmd.Run(); err != nil {
				recordFailure(fmt.Sprintf("Failed to install Python libraries in venv: %v. Ensure internet is stable and try running '.\\venv\\Scripts\\activate.bat' then 'pip install -r plugins/requirements.txt' manually.", err))
			} else {
				output.PrintSuccess("Python libraries installed/updated.")
				venvActivated = true
			}
		}
	}
	fmt.Println()

	if runtime.GOOS == "windows" {
		output.PrintInfo("Checking/Setting PowerShell Execution Policy (Windows only)...")
		cmd = exec.Command("powershell", "-Command", "Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err = cmd.Run(); err != nil {
			output.PrintWarning("Failed to set PowerShell Execution Policy: %v. This might affect virtual environment activation for manual runs.", err)
		} else {
			output.PrintSuccess("PowerShell Execution Policy set to RemoteSigned for current user.")
		}
		fmt.Println()
	}

	if checkCommand("go", "--version") && checkCommand("git", "--version") && checkCommand("protoc", "--version") && pythonFound && venvActivated {
		output.PrintInfo("Running Protobuf code generation and Go build...")
		generateProtoBat = "./generate_proto.bat"
		if runtime.GOOS != "windows" {
			generateProtoBat = "./generate_proto.sh"
		}

		cmd = exec.Command(generateProtoBat)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err = cmd.Run(); err != nil {
			recordFailure(fmt.Sprintf("Failed to generate Protobuf code or build Revealr: %v. Check output above for details.", err))
		} else {
			output.PrintSuccess("Protobuf code generated and Revealr built successfully.")
		}
	} else {
		if !checkCommand("go", "--version") {
			recordFailure("Skipped Protobuf generation and Go build: Go is not installed.")
		}
		if !checkCommand("git", "--version") {
			recordFailure("Skipped Protobuf generation and Go build: Git is not installed.")
		}
		if !checkCommand("protoc", "--version") {
			recordFailure("Skipped Protobuf generation and Go build: Protoc is not installed.")
		}
		if !pythonFound {
			recordFailure("Skipped Protobuf generation and Go build: Python 3.x is not installed.")
		}
		if !venvActivated && pythonFound {
			recordFailure("Skipped Protobuf generation and Go build: Python venv or libraries failed to set up.")
		}
	}
	fmt.Println()

	output.PrintInfo("Checking for existing database for cleanup...")
	if _, err = os.Stat(dbFile); err == nil {
		fmt.Printf("%sFound existing database: %s%s\n", output.Yellow, dbFile, output.Reset)
		fmt.Printf("%sDo you want to delete the existing database file to ensure a clean scan? (Y/N): %s", output.Yellow, output.Reset)

		reader = bufio.NewReader(os.Stdin)
		input, _ = reader.ReadString('\n')
		input = strings.TrimSpace(strings.ToLower(input))

		if input == "y" {
			if err = os.Remove(dbFile); err != nil {
				recordFailure(fmt.Sprintf("Failed to delete database file: %v. Please delete it manually.", err))
			} else {
				output.PrintSuccess("Database file deleted. A new one will be created on next scan.")
			}
		} else {
			output.PrintInfo("Skipping database deletion.")
		}
	} else {
		output.PrintInfo("No existing database found for cleanup.")
	}
	fmt.Println()

	fmt.Printf("\n%s==================================================%s\n", output.Green, output.Reset)
	if len(failureMessages) > 0 {
		output.PrintError("Revealr Setup Wizard finished with %d FAILURES. Please address the following issues:", len(failureMessages))
		for i, msg := range failureMessages {
			output.PrintError("  %d. %s", i+1, msg)
		}
		fmt.Printf("%s==================================================%s\n", output.Red, output.Reset)
	} else {
		output.PrintSuccess("Revealr Setup Wizard finished successfully. All requirements met!")
		fmt.Printf("%s==================================================%s\n", output.Green, output.Reset)
	}
	output.PrintInfo("You can now run Revealr: ./cmd/revealr/revealr.exe scan --target example.com")
	fmt.Println()
}

// checkCommand checks if a command exists in PATH and is executable.
func checkCommand(name string, args ...string) bool {
	cmd := exec.Command(name, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			if exitError.ExitCode() == 127 || exitError.ExitCode() == 9009 {
				return false
			}
		} else if strings.Contains(err.Error(), "executable file not found") || strings.Contains(err.Error(), "The system cannot find the file specified") {
			return false
		}
	}
	return true
}

// checkPython checks if Python 3.x is available and returns its path.
func checkPython() (string, bool) {
	pythonExec := "python"
	if runtime.GOOS == "windows" {
		pythonExec = "python.exe"
	}

	cmd := exec.Command(pythonExec, "--version")
	outputBytes, err := cmd.CombinedOutput()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			_ = exitError
		} else if strings.Contains(string(outputBytes), "not found") || strings.Contains(err.Error(), "executable file not found") || strings.Contains(err.Error(), "The system cannot find the file specified") {
			return "", false
		}
		output.PrintWarning("Python found, but version check failed: %v (Output: %s)", err, strings.TrimSpace(string(outputBytes)))
		return pythonExec, true
	}

	if !strings.Contains(strings.ToLower(string(outputBytes)), "python 3.") {
		output.PrintWarning("Python found, but it's not Python 3.x. Found: %s", strings.TrimSpace(string(outputBytes)))
		return pythonExec, false
	}

	return pythonExec, true
}
