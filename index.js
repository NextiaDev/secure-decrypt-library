const openpgp = require("openpgp");

class DecoderHelper {
  constructor(publicKey, privateKey, secret) {
    this.publicKey = publicKey;
    this.privateKey = privateKey;
    this.secret = secret;
  }

  encryptSingleValue = async (value) => {
    try {
      const { verificationKeys, decryptionKeys } = await this.buildDecryptKey();

      const message = await openpgp.createMessage({ text: value });

      const encrypted = await openpgp.encrypt({
        message, // input as Message object
        encryptionKeys: verificationKeys,
        signingKeys: decryptionKeys,
      });

      const b64 = Buffer.from(encrypted).toString("base64");

      return b64;
    } catch (error) {
      return {
        type: "ERROR",
        message: "Error al encriptar",
      };
    }
  };

  decryptSingleValue = async (value) => {
    try {
      const armoredMessage = this.decryptBase64Data(value);

      const decrypted = await this.onDecryptData(armoredMessage);
      return decrypted;
    } catch (error) {
      return {
        type: "ERROR",
        message: "Error al desencriptar",
      };
    }
  };

  decryptBase64Data = (data) => {
    const buff = Buffer.from(data, "base64");
    return buff.toString("ascii");
  };

  buildDecryptKey = async () => {
    const verificationKeys = await openpgp.readKey({
      armoredKey: this.publicKey,
    });
    const decryptionKeys = await openpgp.decryptKey({
      privateKey: await openpgp.readPrivateKey({
        armoredKey: this.privateKey,
      }),
      passphrase: this.secret,
    });

    return {
      verificationKeys,
      decryptionKeys,
    };
  };

  onDecryptData = async (armoredMessage) => {
    const { verificationKeys, decryptionKeys } = await this.buildDecryptKey();

    const message = await openpgp.readMessage({
      armoredMessage, // parse armored message
    });
    const { data: decrypted, signatures } = await openpgp.decrypt({
      message,
      verificationKeys, // optional
      decryptionKeys,
    });

    return decrypted;
  };

  /**
   * @returns
   * NULL - If the data could NOT be decrypted
   * JSON - If the data could be decrypted
   */
  decodeDataLogin = async (data) => {
    try {
      const armoredMessage = this.decryptBase64Data(data);

      const decrypted = await this.onDecryptData(armoredMessage);
      return {
        user: decrypted.split(":")[0],
        pass: decrypted.split(":")[1],
      };
    } catch (error) {
      return {
        type: "ERROR",
        message: "Error al desencriptar",
      };
    }
  };

  /**
   *
   * @param data - Type JSON - Example :
   * { name: encrypted,
   *   lastName: encrypted
   * }
   *
   * @returns Object Immutable - Example:
   * {
   *  name: decrypted,
   *  lastName: decrypted
   * }
   */
  async decodeJSON(JSONdata) {
    let response = {};

    for (const key in JSONdata) {
      try {
        const value = JSONdata[key];

        if (value === "") {
          response[key] = "";
        } else {
          const armoredMessage = this.decryptBase64Data(value);

          const decrypted = await this.onDecryptData(armoredMessage);
          response[key] = decrypted;
        }
      } catch (error) {
        return {
          type: "ERROR",
          message: "Error al desencriptar",
        };
      }
    }

    return response;
  }
}

// export default DecoderHelper;
module.exports.DecoderHelper = DecoderHelper;

// var reference = async () => {
//   console.log("hola");
//   let Desen = new DecoderHelper(
//     "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxjMEYesehhYJKwYBBAHaRw8BAQdANmpZ+I3yfdXV8II2sVgYzB9TVSht3D6f\n3FkvBhSGlc/NIEluZm9uYXZpdCA8YWNjZXNvQGluZm9uYXZpdC5vcmc+wowE\nEBYKAB0FAmHrHoYECwkHCAMVCAoEFgACAQIZAQIbAwIeAQAhCRCMSckQck8/\nBBYhBODPcfYDJN9YfCn3s4xJyRByTz8EvSIBANzDzDNioo2PcUmI5JTxy26q\nEpeTR/OvEJqUJGbZq5nyAP46CLA7BkrNj1fd5jyEyPaCXwnrzPs4EL16gGjc\n/thJCM44BGHrHoYSCisGAQQBl1UBBQEBB0Ab+QXmAGUTdH3Hd6gdDMSEdNGx\ndkiry3/C5jz8Qs1gLQMBCAfCeAQYFggACQUCYesehgIbDAAhCRCMSckQck8/\nBBYhBODPcfYDJN9YfCn3s4xJyRByTz8ET20BAK+FzRfY1MJNY+S0VZsCwaW3\npFyso3DzE+ZpzWG8SmatAP0YA2G4Ujphf7RFjG9+CdnfG+//6VCoJzOIJ9dC\nDMnJAw==\n=pDL6\n-----END PGP PUBLIC KEY BLOCK-----",
//     "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nxYYEYesehhYJKwYBBAHaRw8BAQdANmpZ+I3yfdXV8II2sVgYzB9TVSht3D6f\n3FkvBhSGlc/+CQMI7GfrDRPpIA3g0q4o3mRLQC4CXxVmRWunHWDgfZSVYzPr\nBoHSOqX1dJQMTWHWsH6Dyq0qD0X6aDTB6M1t4uzpGyiVnVGvRpLFp9VGRb3H\ns80gSW5mb25hdml0IDxhY2Nlc29AaW5mb25hdml0Lm9yZz7CjAQQFgoAHQUC\nYesehgQLCQcIAxUICgQWAAIBAhkBAhsDAh4BACEJEIxJyRByTz8EFiEE4M9x\n9gMk31h8KfezjEnJEHJPPwS9IgEA3MPMM2KijY9xSYjklPHLbqoSl5NH868Q\nmpQkZtmrmfIA/joIsDsGSs2PV93mPITI9oJfCevM+zgQvXqAaNz+2EkIx4sE\nYesehhIKKwYBBAGXVQEFAQEHQBv5BeYAZRN0fcd3qB0MxIR00bF2SKvLf8Lm\nPPxCzWAtAwEIB/4JAwiuEhzC9s4L1eCsEi3XzbVkFGUwEWEZPKPLa3mp0dqy\nZV9RMM2wZwC81UqmKhUZ+xgW8SDW5eTWPFH84HbO2wlB+IxP8TYRaYbZCaDQ\nhtNDwngEGBYIAAkFAmHrHoYCGwwAIQkQjEnJEHJPPwQWIQTgz3H2AyTfWHwp\n97OMSckQck8/BE9tAQCvhc0X2NTCTWPktFWbAsGlt6RcrKNw8xPmac1hvEpm\nrQD9GANhuFI6YX+0RYxvfgnZ3xvv/+lQqCcziCfXQgzJyQM=\n=Jp0K\n-----END PGP PRIVATE KEY BLOCK-----\n",
//     "82d58d3dfb91238b495a311eb8539edf5064784f1d58994679db8363ec241c745bef0b446bfe44d66cbf91a2f4e497d8f6b1ef1656e3f405b0d263a9617ac75e"
//   );

//   const desen = await Desen.decodeJSON(
//     JSON.parse(`{
//     "nss": "LS0tLS1CRUdJTiBQR1AgTUVTU0FHRS0tLS0tCgp3VjREQ09WU1g2VXhTc2NTQVFkQUl5VHhhNUYxWm5iNkg0dS9ZTWNCQ2VDVzlDc05oZXdrc0h5eGhFaDgKV0Zrd01BeGdKeXRXeVVGTVZQU0tCYXAwTVZrZWRqL0VrTzhGd3Y5bm8zamRaWEVQeGo2MGxjenpGMlptCmpYUzhIQWdSMGp3QlRiN0ljZWJqbCtBQkRkdlZnSThvS2g0WThYQ25iZnZnTS9MTjlKNUlpRG5haVhFYgpCbFczd1VSMER2aVdNRCtjckhSdExUeUk0dDd3RXprPQo9aHZobwotLS0tLUVORCBQR1AgTUVTU0FHRS0tLS0tCg==",
//     "claseOperacion": "LS0tLS1CRUdJTiBQR1AgTUVTU0FHRS0tLS0tCgp3VjREQ09WU1g2VXhTc2NTQVFkQWlyNGdlS0xMaGNZWFM1S0JIUjlhRGJ6M3VkeWRSS0h2MTNPaVpwUlgKUmpBd0gwSlVGQjR1MkxxRVhEdUducTFFOVA1cjNIYUF4TlErZE5NSkRjNk5BQTVXYkYrZ0l4VFlVL0VUCkwwTFgxTUtEMGpVQmNFeXlIeXhhTlhSbWZkeTljRHNhVUswd0JTZlZCa0s1QmYzRjhTL3pWZkExdG5OMgpUWTV6VjJmazBGOG9vOVhUTG1nN2xRPT0KPXg2dmkKLS0tLS1FTkQgUEdQIE1FU1NBR0UtLS0tLQo="
// }`)
//   );
//   console.log(desen);
// };

// reference();
