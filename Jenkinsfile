import javax.net.ssl.*
import java.security.MessageDigest
import java.io.FileInputStream
import java.security.KeyStore

def jksFile = new File("dummy.jks")
def jksPassword = "dummy@123"

pipeline {
  agent any

  environment {
    SONAR_TOKEN = ""
  }
  stages {
    stage('SSL Ping Generator') {
      steps {
        script {

            def trustStore = KeyStore.getInstance(KeyStore.getDefaultType())
            trustStore.load(new FileInputStream(jksFile), jksPassword.toCharArray())

            def tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            tmf.init(trustStore)

            def trustManagers = tmf.getTrustManagers()

            trustManagers.each { manager ->
                if (manager instanceof X509TrustManager) {
                    def trustManager = (X509TrustManager) manager
                    def trustAnchors = trustManager.getAcceptedIssuers()
                    
                    trustAnchors.each { cert ->
                        def md = MessageDigest.getInstance("SHA-256")
                        def publicKey = cert.getPublicKey()
                        def publicKeyBytes = publicKey.encoded
                        md.update(publicKeyBytes)
                        def pin = md.digest().encodeBase64().toString()
                        println("SSL Pin: $pin")
                    }
                }
            }
        }
      }
    }
  }
}
