# Introduction #

An integrated Python run-time environment has been integrated into the system to provide an easy and rapid way of adding new features or prototyping concepts. The system is able to run multiple Python scripts in parallel, as well as an interactive shell, and exposes API calls to these scripts through which they are able to communicate with the main system.

Each Python script (and possible shell) is run using a dedicated thread within the application's process. This means that process-specific features should be avoided, and that a malfunctioning script is able to bring down the whole application.

However, the Python exception handling is separate so a Python exception will only affect the script instance in which it is encountered. Being run in the same process means also that data can be passed quite easily between different scripts.

Each script is started in a _clean_ Python interpreter, to which the p2pship API is exposed. It is possible (and recommended) to configure a number of library / wrapper scripts to be run within the interpreters before the actual script. See [the section on file paths](PRE#File_paths.md) for more information.

# Configuring #

The Python run-time is enabled with
```
./configure --enable-python
```

## File paths ##

When starting up, the Python subsystem will look for scripts within the folder configured under the `py_scripts` key. Each .py file will be loaded and run in its own interpreter. Each interpreter will be initialized with the .py scripts found in the folder under the `py_lib` configuration key.

By adding the command line option
```
p2pship --shell
```

the p2pship system will start with an interactive Python shell, initialized in the same manner as the ones the scripts run in. Note that currently this is not possible if the GTK thread is started (which it is by default).

A script can be run from an arbitrary location using the command line switch

```
p2pship --run <script>
```

This can be combined with the `--no-scripts` option to prevent any other scripts from running (useful when developing new scripts, and wanting to prevent any interference from other). E.g.,

```
p2pship --no-scripts --run test.py
```

The configuration (settings.conf) options relevant for the Python subsystem are:

| **Key** | **Description** | **Default value** |
|:--------|:----------------|:------------------|
| `py_start_shell` | Whether to start an interactive shell | no                |
| `py_run_script` | A script to run at startup | _empty_           |
| `py_startup_scripts` | Whether the system scripts should be run | yes               |
| `py_lib` | Path to the interpreter initialization files | ~/.p2pship/apps/lib |
| `py_scripts` | Path to the Python scripts to run at startup | ~/.p2pship/apps/scripts |
| `py_data` | Path to the data directories | ~/.p2pship/apps/data |

## Notes & warnings ##

**GTK**

Using GTK within the Python runtime is not recommended. The GTK engine requires a dedicated thread which does not go well when combined with the c-based native system. Apparently, even though the native system would be compiled with a GTK main loop (`./configure --enable-gtk` or an option automatically enabling it [`--enable-meamo`]), Python-side GTK does not seem to work properly with it (results in various faults).

Disabling native-GTK support and using it only from the Python run-time (starting the GTK loop there) might work, but is prone to errors as there should only be one GTK loop for each process, and each Python script runs within the same process. Beware.

**Threading**

Threading does work, but due to the fact that the p2pship proxy is in itself very threaded, adding Python threads into the mix makes it a bit unstable. Effort has been put into trying to prevent problems (= segfaults), but currently it is not 100% safe. In addition to segfaults, you may see data structures starting to loose members as the different environments get mixed up. Running only one script at a time however shouldn't cause any major concerns.

# API #

_todo_

## Wrapper libraries ##

_todo; see the files in py\_lib_

## Native calls ##

_todo; see the calls in pymod.c_

Sections:

### Environment, logging, configuration ###

### Overlay handling, P2P communication ###

### IPC ###

### HTTP server ###

### Persistant storage ###

### Identity management ###

### SIP ###

### Media engine ###