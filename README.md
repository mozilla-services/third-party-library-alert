# third-party-library-alert
A tool to alert when third party libraries embedded in the FF source code go out of date.

# Types of alerts

The types of library checks we can perform are below. We can add more of course, but these are the easiest ones.

### Release Version

We have a README.mozilla file that says something like "The current version is 1.2.3", and we check against the latest released version of the library and alert when it changes from 1.2.3 to something newer.

### Release Version by Commit

We have a README.mozilla file that says something like "The current version is commit 0987654321123456789abc (Mar 31, 2016)". Even though we identify it by commit, we only update it when the library cuts a new release. So we compare the date in the README file with the date of the latest library release and alert when a new release comes out.

### Commit by Commit

We have a README.mozilla file that says something like "The current version is commit 0987654321123456789abc (Mar 31, 2016)". On this project; however, we don't wait for releases (or maybe upstream doesn't do releases) so we just update it ad-hoc to anew commit when we want or need to.

This one is trickier. What we do is look for new commits, and raise an alert if there is a new commit that is older than N days (where you pick N.) So for example, We're at revision 5 of libfoo, and on Mar 1 revision 6 comes out. On Mar 16th (assuming a 15 day delay) we would open a bug about Revision 6. 

### Commit by Commit File by File

Sometimes we import parts of a library that's really big. Like when we took parts of fdlibm from FreeBSD. We don't want to alert on every commit made to FreeBSD! So instead we check if there's a newer commit on the specific files we imported.  (We can do this if the list of files isn't too large - it really slows down the version check.)

### Other

If you need something that isn't here, we can talk about it and figure out how hard it would be to build.

# hook

https://tools.taskcluster.net/hooks/#project-releng/misc-third-party-library-alert-service
