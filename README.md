# Readme and how to use instructions

This is mule, a module for quasar servers that interfaces to SNMP devices.
The module is hardware agnostic.

In order to deploy it please follow the steps described below:

## Setup quasar project with mule

* There are 2 files that play a role here. First we need to take care of ```ProjectSettings.cmake```. We should set a new ```CUSTOM_SERVER_MODULES``` by declaring mule.

```
set(CUSTOM_SERVER_MODULES mule)
```

* We will also need to declare where the link libraries for Net-SNMP are located if they are not already accessible. To do that we need to 

```
set(SERVER_LINK_LIBRARIES -lnetsnmp )
```

in case the Net-SNMP libraries where installed in a non-standard path, one should point to that path by setting the ```SERVER_LINK_DIRECTORIES``` accordingly.

* An example cmake file for the quasar project is included in the repository under the directory Demo. Additionally, a way to setup your envirnment is suggested and can be reused. It required that you have CVMFS access. If you dont know how to do that, following the instructions on this link: https://cernvm.cern.ch/portal/filesystem/quickstart



