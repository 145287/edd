# Developer Setup

This document describes how to get a development environment configured for modifying or
contributing to EDD.

## Contents
* [Mac OS Setup](#MacOS_Setup)
    * [XCode](#XCode)
    * [HomeBrew](#HomeBrew)
    * [Docker](#Docker)
* [Linux / Debian](#Debian)
* Common Setup Tasks

---------------------------------------------------------------------------------------------------

### Mac OS Setup <a name="MacOS_Setup"/>

This section contains directions for setting up a development environment for EDD on Mac OS.

* XCode <a name="XCode"/>
    * Install XCode (and associated Developer Tools) via the App Store
    * As of OS X 10.9 "Mavericks": `xcode-select --install` to just get command-line tools
* Homebrew <a name="HomeBrew"/>
    * [Homebrew][1] is a package manager for OS X. The Homebrew packages handle installation and
      dependency management for Terminal software. The Caskroom extension to Homebrew does the
      same for GUI applications.
    * To install:
      `ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"`
      and follow prompts.
    * `brew doctor` should say `Your system is ready to brew.` or describe any problems.
    * From the edd root directory, `brew bundle` should install additional software dependencies.
    * It is a good idea to occaisionally run `brew update` to refresh Homebrew's list of available
      packages and versions; and run `brew upgrade` to install updated versions of your installed
      Homebrew packages.
* Docker <a name="Docker"/>
    * [Docker][2] is a container virtualization platform: all software, configuration, and
      dependencies required to run a service are packaged into standalone images. These images are
      ready to run immediately upon being copied to a new host running a Docker daemon.
    * Docker will be installed already via Homebrew in the previous step.
    * Set up Docker Machine; a tool to manage Docker daemons running on other hosts.
        * Create a VM to run containers:
          `docker-machine create --driver virtualbox default`
        * Confirm VM is running with:
          `docker-machine ls`
        * Stop and start VMs with:
          `docker-machine stop default` and `docker-machine start default`
        * Configure the `docker` command to use the virtualbox VM as the container host:
          `eval "$(docker-machine env default)"`
        * See more in the [Docker Machine documentation][3]
    * Running Docker images
        * Verify Docker is configured by running: `docker run --rm hello-world`
            * Get `docker: command not found`? You didn't successfully install from Homebrew.
            * Get `docker: Cannot connect to the Docker daemon.`? You have not run the `eval`
              command in the Docker Machine section.
    * Try the command `docker-compose`
        * If you get `Illegal instruction: 4`, you have an older Mac that cannot run with the
          compiled binary provided by the Homebrew packages; run `pip install docker-compose` to
          fix the error.
        * Normal output is helptext showing the commands to use with `docker-compose`.
    * Setting up Docker for EDD
        * The default virtualbox settings allocate 1 CPU core and 1 GB RAM for the container host
          VM. This should be fine for small or testing deployments. For better performance, it is
          recommended to increase the allocated resources to at least 2 CPU and 2 GB RAM, by
          stopping the VM and changing settings in the "System" tab of the virtualbox
          Settings GUI.
* Complete "Common Setup Tasks" below to get EDD configured and running for the first time
* Complete the "For Developers" section below for a few additional development configurations

### Linux / Debian Setup<a name="Debian"/>

This section contains directions for setting up a production deployment for EDD on Debian.

* Follow the Docker-recommended instructions for [installing the daemon for your distro][5].
    * There is a `docker` package in the Debian apt repos. It isn't [Docker][2]!
    * There is a `docker.io` package too; this can work, but it will generally be outdated.
* Create a user for running EDD; assuming user `jbeideploy` exists for further instructions.
* As `jbeideploy`, check out code to `/usr/local/edd/` (this will be `$EDD_HOME` below)
  
    git clone https://github.com/JBEI/edd.git
    git checkout [release_branch]

* Set up your local docker-machine to manage a remote EDD deployment
    * _If using Docker client on a different host, i.e. with `docker-machine`_
        * Ensure you have a public key in `jbeideploy`'s `~/.ssh/authorized_keys2` file
        * Create an environment for the remote host (replace `{REMOTE_HOST}` with hostname or IP)

              docker-machine create --driver generic \
                  --generic-ip-address {REMOTE_HOST} \
                  --generic-ssh-user jbeideploy \
                  --generic-ssh-key /path/to/private.key \
                  {NAME_OF_ENVIRONMENT}

        * Activate the machine with `eval $(docker-machine env {NAME_OF_ENVIRONMENT})`
        * _NOTE_: Volume mounting directories will use the directories of the host running Docker
          Engine. If you, e.g. try to mount a local.py file, that file _must_ exist at that path
          on the _remote_ host.
    * Test by running `docker-compose`
* Complete "Common Setup Tasks" below now that Docker is in place


### Common Setup Tasks
After you have all of the Docker tools minimally configured for your environment, perform the
following steps in the EDD checkout directory to configure EDD and launch it for the first time.

* __Run `./init-config.sh`__
  This script will:
    * Test your git configuration
    * Copy sample configuration files
    * Generate random passwords for use in autoconfiguring EDD's Docker services

* __Configure `secrets.env`__

  To save work later, you may want to manually edit `secrets.env` to set memorable passwords
  of your choosing for EDD services whose web interfaces are exposed via EDD's nginx proxy,
  or that you intend to expose on your host. For example, services such as RabbitMQ and Flower
  passwords are established during container startup, so make certain you have edited these files
  prior to starting containers. You will also need to update this file when configuring some
  passwords to enable EDD services to communicate with each other.

  After setting passwords in `secrets.env`, you can come back and perform more detailed
  configuration of EDD and Docker later without adding too much work.

* __Build EDD's Docker Images__
    * Make sure you are targeting the correct Docker machine. In the local development example
      above, run `eval "$(docker-machine env default)"`. If you are using Docker Compose to launch
      EDD on a remote host, your command will be different, and you should make sure you are
      executing Docker on the correct host.
    * Run `docker-compose build` to build the Docker containers for EDD. This will take a while. In
      the future, we may publish pre-built Docker images that will prevent you from having to take
      this step.
        * If you run into issues with an image failing to build, with errors looking like
          `E: Failed to fetch $foo  Error reading from server. Remote end closed connection`
          try running `docker-compose build --pull SERVICE_NAME` to always pull latest base images.
          Because the base image updates frequently, sometimes dependencies get mismatched.
    * You can actually skip this step and just run the command to start EDD, but it's included here
      to familiarize developers / maintainers with the Docker build process in case they have to
      run it later.
* __Launch EDD's services__

  Run `docker-compose up -d`. At this point, you can use Docker commands to view the logs for
  each service or to locate the IP for viewing EDD's web interface.

  See "Running EDD" below for a list of helpful commands. If you skipped the previous step, this
  command will take significantly longer the first time you run it, since Docker has to initially
  build / configure the EDD services before they can run.

* __Perform other [configuration][6] as desired__

  For example, by default, EDD will launch with an empty database, so you may want to use
  environment variables to load an existing database.
    * If you're starting from a blank database, use the web interface to configure EDD for your
      institution.
    * If you haven't loaded EDD from an existing database, you'll need to create an administrator
      account from the command line that you can then use to create measurement types, units, and
      other user accounts to get the system going.
        1. Create an administrator account:
          `docker-compose exec edd python /code/manage.py createsuperuser`
        2. Configure EDD using the web interface

           If you need to add any custom metadata types, units, etc. not provided by the default
           installation, use the "Administration" link at top right to add to or remove EDD's
           defaults. It is recommended that you leave defaults in place for consistency with
           collaborators' EDD deployments.
    * Manually set the hostname in EDD's database.

      EDD needs the hostname users will use to access it, which may not be the same as the one
      available to EDD via the host operating system. This value will be used most often to create
      experiment links in ICE, so an incorrect value will cause users to see bad experiment links
      to EDD when viewing ICE parts.
          
      Use the "Administration" link at top right, then scroll down to the "Sites" heading and
      click the "Sites" link under it. Change the value from `edd.example.org`, to your hostname.

* __Install and configure a supporting [ICE][7] deployment__

  EDD requires ICE as a reference for strains used in EDD's experiments. You will not be able to
  reference strains in your EDD studies until EDD can successfully communicate/authenticate
  with ICE.
    * Follow ICE's directions for installation/setup
    * Create a base-64 encoded HMAC key to for signing communication from EDD to ICE. EDD's default
      configuration assumes a key ID of 'edd', but you can change it by overriding the value of
      `ICE_KEY_ID` in your `local.py`. For example, to generate a random 64-byte/512-bit key:

          openssl rand -base64 64 | tr -d '\n' > hmac.key

    * Configure ICE with the HMAC key. In the `rest-auth` folder of the linked ICE deployment, copy
      the `hmac.key` file above to a file named with `ICE_KEY_ID`; 'edd' by default.
    * Configure EDD with the HMAC key. Edit `secrets.env` to set the value of `ICE_HMAC_KEY` to the
      value inside `hmac.key`. Do a `docker-compose restart` if you already had Docker running.
    * See directions under Common 'Maintenance/Development Tasks' to test EDD/ICE communication


### For Developers:

* There is configuration already in place to help you work on EDD. Uncomment support for the Django
  debug toolbar in the sample `local.py` file
* The EDD makes use of Node.js and grunt for builds; it would be a good idea to:
    * OS X:
        * Install node; this is already included in the Brewfile
        * Install the grunt command line: `npm install -g grunt-cli`
        * Install node packages to the local folder: `npm install`
    * Debian:
        * `sudo apt-get install node`
        * This will install nodejs. It may be convenient for you to link this to ‘node’
          on the command line, but there is sometimes already a program
          ’/usr/sbin/ax25-node’ linked to node.
          This is the “Amateur Packet Radio Node program” and is probably not useful to you.
          (https://packages.debian.org/sid/ax25-node)
          Check on this link with `ls -al /usr/sbin/n*` and `rm /usr/sbin/node` if necessary, then
          `sudo ln -s /usr/bin/nodejs /usr/bin/node`
        * `sudo apt-get install npm`
        * `sudo npm install -g grunt-cli`
        * `sudo npm install grunt`
* EDD uses [TypeScript][4] for its client-side interface
    * Dependencies are listed in `packages.json` and may be installed with `npm install`
    * Compile changes in `*.ts` to `*.js` by simply running `grunt` from the edd base
      directory. It will rebuild the TypeScript and automatically run Django's `collectstatic`
      command to update the Javascript files in use by your instance.

#### Additional Build Process Setup

The TypeScript build process includes some comments that will change with every rebuild. These
comments will cause unnecessary merge conflicts if allowed into the repo, so the project includes
some configuration to strip them out.

After cloning the repo for the first time run `.gitconfig.sh`. If updating an existing repo, you
may need to add changed files to the index once. Some bundled git versions are outdated and cannot
use the configuration contained in the script; you may need to install a newer version of git;
[Homebrew](#HomeBrew) instructions above will install a more recent version on Macs.

#### Helpful Python Packages <a name="Helpful_Python"/>

* django-debug-toolbar `pip install django-debug-toolbar`
    * Include `debug_toolbar` in `./edd/settings/local.py` INSTALLED_APPS

---------------------------------------------------------------------------------------------------

[1]:    http://brew.sh
[2]:    https://docker.io
[3]:    https://docs.docker.com/machine/overview/
[4]:    http://typescriptlang.org/
[5]:    https://docs.docker.com/engine/installation/linux/
[6]:    docs/Configuration.md
[7]:    https://github.com/JBEI/ice