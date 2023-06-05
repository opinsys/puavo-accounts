pipeline {
  agent {
    dockerfile {
      filename 'Dockerfile'

      // XXX could you do most operations as normal user?
      args '-u root --mount type=bind,source=/etc/jenkins-docker-config,destination=/etc/jenkins-docker-config,readonly --env-file=/etc/jenkins-docker-config/environment --privileged --tmpfs /run --tmpfs /run/lock --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw'
    }
  }

  stages {
    stage('Fix repository permissions') {
      steps { sh 'chown -R root:root .' }
    }

    stage('Prepare') {
      steps {
        sh '''
          apt-get update
          apt-get -y dist-upgrade
          apt-get install -y devscripts dpkg-dev make rsync wget
        '''
      }
    }

    stage('Install deb-package build dependencies') {
      steps {
        sh 'make install-build-deps'
      }
    }

    stage('Build') {
      steps { sh 'make deb' }
    }

    stage('Upload') {
      steps {
        sh '''
          install -o root -g root -m 644 /etc/jenkins-docker-config/dput.cf \
            /etc/dput.cf
          install -o root -g root -m 644 \
            /etc/jenkins-docker-config/ssh_known_hosts \
            /etc/ssh/ssh_known_hosts
          install -d -o root -g root -m 700 ~/.ssh
          install -o root -g root -m 600 \
            /etc/jenkins-docker-config/sshkey_puavo_deb_upload \
            ~/.ssh/id_rsa
        '''

        sh 'make upload-debs'
      }
    }
  }
}
