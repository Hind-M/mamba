import os
import random
import shutil
import string
import subprocess
import tempfile
from sys import platform

import pytest

from .helpers import create, get_umamba, random_string, subprocess_run, umamba_run

common_simple_flags = ["", "-d", "--detach", "--clean-env"]
# -d/--detach are not available on Windows (see run.cpp)
common_simple_flags_for_help = (
    [f for f in common_simple_flags if f not in ("-d", "--detach")]
    if platform == "win32"
    else common_simple_flags
)
possible_characters_for_process_names = (
    "-_" + string.ascii_uppercase + string.digits + string.ascii_lowercase
)


def generate_label_flags():
    random_string = "".join(random.choice(possible_characters_for_process_names) for _ in range(16))
    return ["--label", random_string]


next_label_flags = [lambda: [], generate_label_flags] if platform != "win32" else []


def simple_short_program():
    return "ls" if platform != "win32" else "dir"


class TestRun:
    current_root_prefix = os.environ["MAMBA_ROOT_PREFIX"]
    current_prefix = os.environ["CONDA_PREFIX"]

    @pytest.mark.parametrize("option_flag", common_simple_flags)
    @pytest.mark.parametrize("make_label_flags", next_label_flags)
    def test_fail_without_command(self, option_flag, make_label_flags):
        with pytest.raises(subprocess.CalledProcessError):
            umamba_run(option_flag, *make_label_flags())

    @pytest.mark.parametrize("option_flag", common_simple_flags)
    @pytest.mark.parametrize("make_label_flags", next_label_flags)
    def test_unknown_exe_fails(self, option_flag, make_label_flags):
        fails = True
        try:
            umamba_run(option_flag, *make_label_flags(), "exe-that-does-not-exists")
            fails = False
        except subprocess.CalledProcessError:
            fails = True

        # In detach mode we fork micromamba and don't have a way to know if the executable exists.
        if option_flag == "-d" or option_flag == "--detach":
            assert fails is False
        else:
            assert fails is True

    @pytest.mark.parametrize("option_flag", common_simple_flags_for_help)
    # @pytest.mark.parametrize("label_flags", naming_flags()) # TODO: reactivate after fixing help flag not disactivating the run
    @pytest.mark.parametrize("help_flag", ["-h", "--help"])
    @pytest.mark.parametrize("command", ["", simple_short_program()])
    def test_help_succeeds(self, option_flag, help_flag, command):
        res = umamba_run(option_flag, help_flag, command)
        assert len(res) > 0

    @pytest.mark.parametrize("option_flag", common_simple_flags)
    @pytest.mark.parametrize("make_label_flags", next_label_flags)
    def test_basic_succeeds(self, option_flag, make_label_flags):
        res = umamba_run(option_flag, *make_label_flags(), simple_short_program())
        print(res)
        assert len(res) > 0

    @pytest.mark.skipif(platform == "win32", reason="bash specific test")
    @pytest.mark.parametrize("inp", ["(", "a\nb", "a'b\""])
    def test_quoting(self, inp):
        res = umamba_run("echo", inp)
        assert res.strip() == inp

    @pytest.mark.skipif(platform == "win32", reason="requires bash to be available")
    def test_shell_io_routing(self):
        test_script_file_name = "test_run.sh"
        test_script_path = os.path.join(os.path.dirname(__file__), test_script_file_name)
        if not os.path.isfile(test_script_path):
            raise RuntimeError(
                f"missing test script '{test_script_file_name}' at '{test_script_path}"
            )
        subprocess_run(test_script_path, shell=True)

    def test_run_non_existing_env(self):
        env_name = random_string()
        try:
            umamba_run("-n", env_name, "python")
        except subprocess.CalledProcessError as e:
            assert "critical libmamba The given prefix does not exist:" in e.stderr.decode()

    def test_run_non_existing_cwd(self):
        cwd = random_string()
        try:
            umamba_run("--cwd", cwd, "python")
        except subprocess.CalledProcessError as e:
            assert "critical libmamba The given path does not exist:" in e.stderr.decode()


@pytest.fixture()
def temp_env_prefix():
    previous_root_prefix = os.environ["MAMBA_ROOT_PREFIX"]
    previous_prefix = os.environ["CONDA_PREFIX"]

    env_name = random_string()
    root_prefix = os.path.expanduser(os.path.join("~", "tmproot" + random_string()))
    prefix = os.path.join(root_prefix, "envs", env_name)

    os.environ["MAMBA_ROOT_PREFIX"] = root_prefix
    create("-p", prefix, "python")

    yield prefix

    shutil.rmtree(prefix)
    os.environ["MAMBA_ROOT_PREFIX"] = previous_root_prefix
    os.environ["CONDA_PREFIX"] = previous_prefix


@pytest.fixture()
def broken_shell_bin(tmp_path):
    """Directory holding an executable `bash` that fails at exec time
    (missing shebang interpreter -> execve ENOENT -> proc.start() fails)."""
    fake_bin = tmp_path / "fakebin"
    fake_bin.mkdir()
    fake_bash = fake_bin / "bash"
    fake_bash.write_text("#!/nonexistent/interpreter\n")
    fake_bash.chmod(fake_bash.stat().st_mode | 0o111)
    return fake_bin


class TestRunVenv:
    def test_classic_specs(self, temp_env_prefix):
        res = umamba_run("-p", temp_env_prefix, "python", "-c", "import sys; print(sys.prefix)")
        assert res.strip() == temp_env_prefix

    # TODO check skipping, only macos? platform != "darwin" or keep running on unix?
    @pytest.mark.skipif(
        platform == "win32", reason="Non-TTY repro is macOS specific? (mamba-org/mamba#4165)"
    )
    def test_non_tty_redirected_stdio(self, temp_env_prefix):
        umamba = get_umamba()
        cmd = [umamba, "run", "-p", temp_env_prefix, "python", "--version"]
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = os.path.join(tmp_dir, "output")
            # Emulate a non-interactive runner: stdin=/dev/null, stdout+stderr -> same file (2>&1)
            with open(output_path, "w") as output_file:
                result = subprocess.run(
                    cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=output_file,
                    stderr=subprocess.STDOUT,
                    check=False,
                )
            with open(output_path) as output_file:
                output = output_file.read()
        # assert result.returncode == 0, f"`mamba run` failed with non-TTY stdio:\n{output}"
        # assert "Python" in output
        print("result: ", result)
        print("output: ", output)

    # TODO check skipping, only macos? platform != "darwin" or keep running on unix?
    @pytest.mark.skipif(
        platform == "win32", reason="Non-TTY repro is macOS specific? (mamba-org/mamba#4165)"
    )
    @pytest.mark.parametrize("detach_flags", [[], ["-d"]])
    def test_run_start_failure_reports_real_error(
        self, temp_env_prefix, broken_shell_bin, tmp_path, detach_flags
    ):
        env = dict(os.environ)
        env["PATH"] = os.pathsep.join([str(broken_shell_bin), env["PATH"]])

        output_path = tmp_path / "output"
        with open(output_path, "w") as output_file:
            result = subprocess.run(
                [get_umamba(), "run", *detach_flags, "-p", temp_env_prefix, "python", "--version"],
                env=env,
                stdin=subprocess.DEVNULL,  # < /dev/null
                stdout=output_file,  # > file
                stderr=subprocess.STDOUT,  # 2>&1
                check=False,
            )
        output = output_path.read_text()

        print("result: ", result)
        print("output: ", output)
        # assert result.returncode != 0
        # assert "Undefined error" not in output, output
        # assert "Success" not in output, output
        # assert "; error code " in output, output
