local typedefs = require "kong.db.schema.typedefs"

return {
  name = "ali-functions",
  fields = {
    { protocols = typedefs.protocols },
    {
      config = {
        type = "record",
        fields = {
          -- authorization
          {
            accesskeyid = {
              description =
              "The key id to access the Ali resources. If provided, it is used to generate the signature in authorization header.",
              type = "string",
              encrypted = true,
              referenceable = true
            },
          }, -- encrypted = true is a Kong Enterprise Exclusive feature. It does nothing in Kong CE
          {
            accesskeysecret = {
              description =
              "The key secret to access the Ali resources. If provided, it is used to generate the signature in authorization header.",
              type = "string",
              encrypted = true,
              referenceable = true,
            },
          }, -- encrypted = true is a Kong Enterprise Exclusive feature. It does nothing in Kong CE
          -- target/location
          {
            hostdomain = {
              description = "The domain where the function resides.",
              type = "string",
              required = true,
              default = "https://1925906418026005.cn-shanghai.fc.aliyuncs.com",
            },
          },
          {
            tenantid = {
              description = "The ali tenant where the function resides.",
              type = "string",
              required = true,
            },
          },
          {
            hostlocation = {
              description = "The location where the function resides.",
              type = "string",
              required = true,
              default = "cn-shanghai",
            },
          },
          {
            functionname = {
              description = "Name of the Ali function to invoke.",
              type = "string",
              required = true,
            },
          },
          {
            servicename= {
              description = "The Ali funcion 2.0 service name.",
              type = "string",
              required = false
            },
          },
          {
            functionversion= {
              description = "The Ali funcion compute version. 3.0 or 2.0",
              type = "string",
              required = true,
              default = "3.0",
            },
          },
          {
            apiversion= {
              description = "The Ali funcion compute api version.",
              type = "string",
              required = true,
              default = "2023-03-30",
            },
          },
          -- connection basics
          {
            timeout = {
              description = "Timeout in milliseconds before closing a connection to the Ali Functions server.",
              type = "number",
              default = 600000,
            },
          },
          {
            keepalive = {
              description =
              "Time in milliseconds during which an idle connection to the Ali Functions server lives before being closed.",
              type = "number",
              default = 60000
            },
          },
          {
            https = {
              type = "boolean",
              default = true,
              description = "Use of HTTPS to connect with the Ali Functions server."
            },
          },
          {
            https_verify = {
              description = "Set to `true` to authenticate the Ali Functions server.",
              type = "boolean",
              default = false,
            },
          },
        },
      },
    },
  }
}
