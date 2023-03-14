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

  async decodeSingleValue(valueEncrypted) {
    const armoredMessage = this.decryptBase64Data(valueEncrypted);
    return await this.onDecryptData(armoredMessage);
  }

  async decodeAllJSONData(bodyEncrypted) {
    // El body se regresa en la siguiente expresion
    const body = {};
    try {
      // Si el body es un objeto
      if (typeof bodyEncrypted === "object") {
        // iteramos por cada key del body
        for (const key in bodyEncrypted) {
          const valueEncrypted = bodyEncrypted[key];

          if (valueEncrypted === "") {
            body[key] = "";
          } else if (Array.isArray(valueEncrypted)) {
            const array = [];
            // Iteramos por cada uno de los elementos del arreglo
            for (const element of valueEncrypted) {
              // Valida si el elemento es vacio
              if (element === "") {
                array.push("");
              }
              // Valida si el elemento es un objeto
              else if (typeof element === "string") {
                array.push(await this.decodeSingleValue(element));
              }
              // Valida si el elemento es un objeto
              else if (typeof element === "object") {
                array.push(await this.decodeAllJSONData(element));
              }
            }
            body[key] = array;
          }
          // Validamos si es un objeto
          else if (typeof valueEncrypted === "object") {
            // Si es un objeto la función se vuelve recursiva
            body[key] = await this.decodeAllJSONData(valueEncrypted);
          }
          // Proceso de encriptado del value del objeto
          else {
            // Proceso para desencriptar
            body[key] = await this.decodeSingleValue(valueEncrypted);
          }
        }
      }
    } catch (error) {
      throw new Error("Error al desencriptar");
    }

    return body;
  }
}

module.exports = DecoderHelper;
