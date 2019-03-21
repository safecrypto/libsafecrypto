# Dockerfile Readme #

This dockerfile creates a container with all required project dependencies installed. It is intended to be used as a development environment after the git clone has been completed so prevent having to pass credentials into the container. In order to modify files in the git repo on the host from within the container, the user/group ids of the container user must match that of the host. This is the function of the usermap.sh script. Note that passing `-u {uid}:{gid}` is possible, however no username is specified and the name on the terminal is "I have no name!". Changing user name/id pairs can only be done when the user is _not_ logged in, hence the ENTRYPOINT script approach is used, as the container starts as root, the id modifcations are made, and the root switches user to developer.

No user home directory is present, the `developer` user was added as a system user only.

The dockerfile is ~2GB when built. this is largely due to the latex packages required in order to build to documents using doxygen. These can be removed if required to reduce the container size.
