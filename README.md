**Java Win32 Process Util**
======================

A utility class for managing Windows processes using JNA (Java Native Access).

**Overview**
------------

This library provides a set of utility methods for creating, managing, and interacting with Windows processes. It leverages JNA to access native Windows APIs, allowing Java applications to perform process-related tasks.

**Features**
------------

*   Create a new process as a user that started a reference process
*   Find the process ID of a reference process
*   Get the process handle of a process by its ID
*   Get the user token of a process
*   Duplicate a token
*   Create a new process as a user with a duplicated token
*   Get the environment variables of a user token

**Usage**
---------

To use this library, simply add the JAR file to your project's classpath and import the `Win32ProcessUtil` class.

```java
import com.github.yashkolte3.win32.utils.Win32ProcessUtil;

// Create a new process as a user that started a reference process
ProcessHandle processHandle = Win32ProcessUtil.createProcessAs("cmd.exe", Optional.of(Path.of("C:\\")), Optional.of("explorer.exe"));

// Find the process ID of a reference process
Optional<Integer> referencePID = Win32ProcessUtil.findReferenceProcessID("explorer.exe");

// Get the process handle of a process by its ID
Optional<WinNT.HANDLE> processHandle = Win32ProcessUtil.getProcessHandle(1234);

// Get the user token of a process
Optional<WinNT.HANDLE> userToken = Win32ProcessUtil.getUserToken(new WinNT.HANDLE());

// Duplicate a token
Optional<WinNT.HANDLE> duplicatedToken = Win32ProcessUtil.duplicateToken(new WinNT.HANDLE());

// Create a new process as a user with a duplicated token
ProcessHandle processHandle = Win32ProcessUtil.createProcessAsUser("cmd.exe", new WinNT.HANDLE(), Optional.of(Path.of("C:\\")));

// Get the environment variables of a user token
Map<String, String> environmentVariables = Win32ProcessUtil.getEnvironmentVariables(new WinNT.HANDLE());
```

**Note:** The readme is generated by AI and may not be 100% accurate or error-free. While every effort has been made to ensure the accuracy and completeness of the code, users are advised to review and test the code thoroughly before using it in production environments.

**Requirements**
---------------

*   Java 8 or later
*   JNA (Java Native Access) library

**Building**
------------

To build this library, simply run the following command in the project root directory:

```bash
mvn clean package
```

This will create a JAR file in the `target` directory.

**License**
----------

This library is licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0).

**Contributing**
------------

Contributions are welcome! If you'd like to contribute to this library, please fork the repository and submit a pull request with your changes.

**Acknowledgments**
-----------------

This library uses the following third-party libraries:

*   JNA (Java Native Access)
*   Apache Commons Lang

Thanks to the developers and maintainers of these libraries for their hard work and contributions to the open-source community.
