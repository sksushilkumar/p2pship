# Introduction #

The AppEngine subsystem is an experiment of adding a run-time environment for native peer-to-peer applications. The basic concept is to have an environment similar to [Google AppEngine](http://code.google.com/appengine/) where applications could be deployed. These applications would be able to access data both through an database-like interface as well as a publish-subscribe interface. The data would be transparently shared throughout all deployments of the same application instance in a secure, privacy preserving manner.

This is currently in planning. It would be built on top of the Python subsystem, but requires new features such as groups and support for publish-subscribe.