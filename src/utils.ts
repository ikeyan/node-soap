
import * as crypto from 'crypto';
import { IDIMEAttachment, IDIMEAttachments, IMTOMAttachments } from './types';

export function passwordDigest(nonce: string, created: string, password: string): string {
  // digest = base64 ( sha1 ( nonce + created + password ) )
  const pwHash = crypto.createHash('sha1');

  const NonceBytes = Buffer.from(nonce || '', 'base64');
  const CreatedBytes = Buffer.from(created || '', 'utf8');
  const PasswordBytes = Buffer.from(password || '', 'utf8');
  const FullBytes = Buffer.concat([NonceBytes, CreatedBytes, PasswordBytes]);

  pwHash.update(FullBytes);
  return pwHash.digest('base64');
}

export const TNS_PREFIX = '__tns__'; // Prefix for targetNamespace

/**
 * Find a key from an object based on the value
 * @param {Object} Namespace prefix/uri mapping
 * @param {*} nsURI value
 * @returns {String} The matching key
 */
export function findPrefix(xmlnsMapping, nsURI) {
  for (const n in xmlnsMapping) {
    if (n === TNS_PREFIX) { continue; }
    if (xmlnsMapping[n] === nsURI) {
      return n;
    }
  }
}

export function splitQName<T>(nsName: T) {
  if (typeof nsName !== 'string') {
    return {
      prefix: TNS_PREFIX,
      name: nsName as Exclude<T, string>,
    };
  }

  const [topLevelName] = nsName.split('|', 1);

  const prefixOffset = topLevelName.indexOf(':');

  return {
    prefix: topLevelName.substring(0, prefixOffset) || TNS_PREFIX,
    name: topLevelName.substring(prefixOffset + 1),
  };
}

export function xmlEscape(obj: string) {
  if (typeof (obj) === 'string') {
    if (obj.substr(0, 9) === '<![CDATA[' && obj.substr(-3) === ']]>') {
      return obj;
    }
    return obj
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&apos;');
  }

  return obj;
}

const DimeFlagsMessageBegin = 0x4;
const DimeFlagsMessageEnd = 0x2;
const DimeFlagsChunkFlag = 0x1;
const DimeDataTypeUnchanged = 0x0;
const DimeDataTypeMediaType = 0x1;
const DimeDataTypeUri = 0x2;
const DimeDataTypeUnknown = 0x3;
const DimeDataTypeNone = 0x4;
type DimeDataType =
  | typeof DimeDataTypeUnchanged
  | typeof DimeDataTypeMediaType
  | typeof DimeDataTypeUri
  | typeof DimeDataTypeUnknown
  | typeof DimeDataTypeNone;

interface DimeRecord {
  flags: number;
  dataType: DimeDataType;
  options: DimeRecordOptionElement[];
  id: string;
  type: string;
  data: Buffer;
}

interface DimeRecordOptionElement {
  type: number;
  data: Buffer;
}

export function parseDIMEResponse(payload: Buffer): IDIMEAttachments {
  const parseRecord = (offset: number): [DimeRecord, number] => {
    const byte0 = payload.readUint8(offset);
    const version = byte0 >> 3;
    if (version !== 1) {
      throw new Error(`Unsupported DIME version: ${version}`);
    }
    const flags = byte0 & 0x7;
    const byte1 = payload.readUint8(offset + 1);
    const dataType = byte1 >> 4;
    switch (dataType) {
      case DimeDataTypeUnchanged:
      case DimeDataTypeMediaType:
      case DimeDataTypeUri:
      case DimeDataTypeUnknown:
      case DimeDataTypeNone:
        break;
      default:
        throw new Error(`Unsupported DIME data type: ${dataType}`);
    }
    if (byte1 & 0xf) {
      throw new Error('Reserved bits must be zero');
    }
    const optionsLength = payload.readUint16BE(offset + 2);
    const idLength = payload.readUint16BE(offset + 4);
    const typeLength = payload.readUint16BE(offset + 6);
    const dataLength = payload.readUint32BE(offset + 8);
    switch (dataType) {
      case DimeDataTypeUnchanged:
        if (idLength !== 0 || typeLength !== 0) {
          throw new Error('Unchanged data type must have zero ID and type length');
        }
        break;
      case DimeDataTypeUnknown:
        if (typeLength !== 0) {
          throw new Error('Unknown data type must have zero type length');
        }
        break;
      case DimeDataTypeNone:
        if (typeLength !== 0 || dataLength !== 0) {
          throw new Error('None data type must have zero type and data length');
        }
        break;
    }
    offset += 12;
    const alignTo4Octets = (offset: number) => (offset + 3) & ~3;
    const optionEndOffset = offset + optionsLength;
    const options: DimeRecordOptionElement[] = [];
    while (offset < optionEndOffset) {
      const type = payload.readUint16BE(offset);
      const length = payload.readUint16BE(offset + 2);
      offset += 4;
      const data = payload.subarray(offset, length);
      offset += length;
      options.push({ type, data });
    }
    if (offset !== optionEndOffset) {
      throw new Error('Options length mismatch');
    }
    offset = alignTo4Octets(offset);
    const id = idLength === 0 ? '' : payload.toString('utf-8', offset, offset + idLength);
    offset = alignTo4Octets(offset + idLength);
    const type = typeLength === 0 ? '' : payload.toString('utf-8', offset, offset + typeLength);
    offset = alignTo4Octets(offset + typeLength);
    const data = payload.subarray(offset, offset + dataLength);
    offset = alignTo4Octets(offset + dataLength);
    return [{ flags, dataType, options, id, type, data }, offset];
  };
  let lastIndex: number | undefined;
  const parts: IDIMEAttachment[] = [];
  const chunks: DimeRecord[] = [];
  for (let i = 0, offset = 0; offset < payload.byteLength; i++) {
    let record: DimeRecord;
    [record, offset] = parseRecord(offset);
    if (i === 0 && !(record.flags & DimeFlagsMessageBegin)) {
      throw new Error('DIME message begin flag is not set in the first record');
    }
    if (i > 0 && (record.flags & DimeFlagsMessageBegin)) {
      throw new Error('DIME message begin flag is set in a non-first record');
    }
    if (lastIndex !== undefined) {
      throw new Error('There is a record after the last record');
    }
    if ((~record.flags & (DimeFlagsChunkFlag | DimeFlagsMessageEnd)) === 0) {
      throw new Error('DIME chunk flag and message end flag cannot be set at the same time');
    }
    if (record.flags & DimeFlagsChunkFlag || chunks.length > 0) {
      if (chunks.length === 0) {
        if (record.dataType === DimeDataTypeUnchanged) {
          throw new Error('DIME data type must not be unchanged in the first chunk record');
        }
      } else {
        if (record.dataType !== DimeDataTypeUnchanged) {
          throw new Error('DIME data type must be unchanged in a subsequent chunk record');
        }
        if (record.id.length > 0) {
          throw new Error('DIME ID must be empty in a subsequent chunk record');
        }
        if (record.type.length > 0) {
          throw new Error('DIME type must be empty in a subsequent chunk record');
        }
      }
      chunks.push(record);
      if (!(record.flags & DimeFlagsChunkFlag)) {
        record = chunks[0];
        record.options = chunks.flatMap((chunk) => chunk.options);
        record.flags &= ~DimeFlagsChunkFlag;
        record.data = Buffer.concat(chunks.map((chunk) => chunk.data));
        chunks.length = 0;
      }
    }
    if (record.flags & DimeFlagsMessageEnd) {
      lastIndex = i;
    }
    switch (record.dataType) {
      case DimeDataTypeMediaType:
        parts.push({
          id: record.id,
          type: {
            type: 'MIME',
            mimeType: record.type,
          },
          body: record.data,
        });
        break;
      case DimeDataTypeUri:
        parts.push({
          id: record.id,
          type: {
            type: 'URI',
            uri: record.type,
          },
          body: record.data,
        });
        break;
      case DimeDataTypeUnknown:
        parts.push({
          id: record.id,
          type: {
            type: 'Unknown',
          },
          body: record.data,
        });
        break;
    }
  }
  return { type: 'DIME', parts };
}

export function parseMTOMResp(payload: Buffer, boundary: string, callback: (err?: Error, resp?: IMTOMAttachments) => void) {
  return import('formidable')
    .then(({ MultipartParser }) => {
      const resp: IMTOMAttachments = {
        type: 'MTOM',
        parts: [],
      };
      let headerName = '';
      let headerValue = '';
      let data: Buffer;
      let partIndex = 0;
      const parser = new MultipartParser();

      parser.initWithBoundary(boundary);
      parser.on('data', ({ name, buffer, start, end }) => {
        switch (name) {
          case 'partBegin':
            resp.parts[partIndex] = {
              body: null,
              headers: {},
            };
            data = Buffer.from('');
            break;
          case 'headerField':
            headerName = buffer.slice(start, end).toString();
            break;
          case 'headerValue':
            headerValue = buffer.slice(start, end).toString();
            break;
          case 'headerEnd':
            resp.parts[partIndex].headers[headerName.toLowerCase()] = headerValue;
            break;
          case 'partData':
            data = Buffer.concat([data, buffer.slice(start, end)]);
            break;
          case 'partEnd':
            resp.parts[partIndex].body = data;
            partIndex++;
            break;
        }
      });

      parser.write(payload);

      return callback(null, resp);
    })
    .catch(callback);
}
