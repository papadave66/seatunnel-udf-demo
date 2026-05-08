# seatunnel-udf-demo
This is a demo project for playing with UDF on Apache Seatunnel.  
Now we have SM2Encrypt, SM2Decrypt, TripleDESEncrypt, TripleDESDecrypt in SQL UDF mode. **(WIP)**

## How to use it
1. Clone this project
2. Use maven to package it as a jar file
3. Copy this jar and other libraries into `$SEATUNNEL_HOME/lib`, like `bcprov-jdk18on-1.83.jar`
4. Edit Seatunnel job. here is the demo job for you to test it.
```
env {
  job.mode = "BATCH"
}

source {
  FakeSource {
    plugin_output = "fake"
    row.num = 100
    schema = {
      fields {
        id = "int"
        name = "string"
        age = "int"
        job = "string"
      }
    }
  }
}

transform {
  Sql {
    plugin_input = "fake"
    plugin_output = "fake1"
    query = "select id, SM2_DECRYPT(SM2_ENCRYPT(name, job)) as sm2_enc from dual"
  }
}


sink {
  Console {
    plugin_input = "fake1"
  }
}
```
