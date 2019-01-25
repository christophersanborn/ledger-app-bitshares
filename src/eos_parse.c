/*******************************************************************************
*
*  This file is a derivative work, and contains modifications from original
*  form.  The modifications are copyright of their respective contributors,
*  and are licensed under the same terms as the original work.
*
*  Portions Copyright (c) 2019 Christopher J. Sanborn
*
*  Original copyright and license notice follows:
*
*   Taras Shchybovyk
*   (c) 2018 Taras Shchybovyk
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#include "eos_parse.h"
#include "os.h"
#include "cx.h"
#include "eos_types.h"
#include "eos_utils.h"
#include <stdbool.h>
#include <string.h>

void printString(const char in[], const char fieldName[], actionArgument_t *arg) {
    uint32_t inLength = strlen(in);
    uint32_t labelLength = strlen(fieldName);

    os_memset(arg->label, 0, sizeof(arg->label));
    os_memset(arg->data, 0, sizeof(arg->data));

    os_memmove(arg->label, fieldName, labelLength);
    os_memmove(arg->data, in, inLength);
}

void parsePublicKeyField(uint8_t *in, uint32_t inLength, const char fieldName[], actionArgument_t *arg, uint32_t *read, uint32_t *written) {
    if (inLength < 33) {
        PRINTF("parseActionData Insufficient buffer\n");
        THROW(EXCEPTION);
    }
    uint32_t labelLength = strlen(fieldName);
    if (labelLength > sizeof(arg->label)) {
        PRINTF("parseActionData Label too long\n");
        THROW(EXCEPTION);
    }

    os_memset(arg->label, 0, sizeof(arg->label));
    os_memset(arg->data, 0, sizeof(arg->data));

    os_memmove(arg->label, fieldName, labelLength);
    uint32_t writtenToBuff = compressed_public_key_to_wif(in, 33, arg->data, sizeof(arg->data)-1);

    *read = 33;
    *written = writtenToBuff;
}

void parseUint16Field(uint8_t *in, uint32_t inLength, const char fieldName[], actionArgument_t *arg, uint32_t *read, uint32_t *written) {
    if (inLength < sizeof(uint16_t)) {
        PRINTF("parseActionData Insufficient buffer\n");
        THROW(EXCEPTION);
    }
    uint32_t labelLength = strlen(fieldName);
    if (labelLength > sizeof(arg->label)) {
        PRINTF("parseActionData Label too long\n");
        THROW(EXCEPTION);
    }
    
    os_memset(arg->label, 0, sizeof(arg->label));
    os_memset(arg->data, 0, sizeof(arg->data));
    
    os_memmove(arg->label, fieldName, labelLength);
    uint16_t value;
    os_memmove(&value, in, sizeof(uint16_t));
    snprintf(arg->data, sizeof(arg->data)-1, "%d", value);
    
    *read = sizeof(uint16_t);
    *written = strlen(arg->data);
}

void parseUint32Field(uint8_t *in, uint32_t inLength, const char fieldName[], actionArgument_t *arg, uint32_t *read, uint32_t *written) {
    if (inLength < sizeof(uint32_t)) {
        PRINTF("parseActionData Insufficient buffer\n");
        THROW(EXCEPTION);
    }
    uint32_t labelLength = strlen(fieldName);
    if (labelLength > sizeof(arg->label)) {
        PRINTF("parseActionData Label too long\n");
        THROW(EXCEPTION);
    }
    
    os_memset(arg->label, 0, sizeof(arg->label));
    os_memset(arg->data, 0, sizeof(arg->data));
    
    os_memmove(arg->label, fieldName, labelLength);
    uint32_t value;
    os_memmove(&value, in, sizeof(uint32_t));
    snprintf(arg->data, sizeof(arg->data)-1, "%d", value);
    
    *read = sizeof(uint32_t);
    *written = strlen(arg->data);
}

void parseUInt64Field(uint8_t *in, uint32_t inLength, const char fieldName[], actionArgument_t *arg, uint32_t *read, uint32_t *written) {
    if (inLength < sizeof(uint64_t)) {
        PRINTF("parseActionData Insufficient buffer\n");
        THROW(EXCEPTION);
    }
    uint32_t labelLength = strlen(fieldName);
    if (labelLength > sizeof(arg->label)) {
        PRINTF("parseActionData Label too long\n");
        THROW(EXCEPTION);
    }
    
    os_memset(arg->label, 0, sizeof(arg->label));
    os_memset(arg->data, 0, sizeof(arg->data));
    
    os_memmove(arg->label, fieldName, labelLength);
    uint64_t value;
    os_memmove(&value, in, sizeof(uint64_t));
    ui64toa(value, arg->data);
    
    *read = sizeof(uint64_t);
    *written = strlen(arg->data);
}

void parseStringField(uint8_t *in, uint32_t inLength, const char fieldName[], actionArgument_t *arg, uint32_t *read, uint32_t *written) {
    uint32_t labelLength = strlen(fieldName);
    if (labelLength > sizeof(arg->label)) {
        PRINTF("parseActionData Label too long\n");
        THROW(EXCEPTION);
    }

    os_memset(arg->label, 0, sizeof(arg->label));
    os_memset(arg->data, 0, sizeof(arg->data));

    os_memmove(arg->label, fieldName, labelLength);

    uint32_t fieldLength = 0;
    uint32_t readFromBuffer = unpack_varint32(in, inLength, &fieldLength);
    if (fieldLength > sizeof(arg->data) - 1) {
        PRINTF("parseActionData Insufficient bufferg\n");
        THROW(EXCEPTION);
    } 

    if (inLength < fieldLength) {
        PRINTF("parseActionData Insufficient buffer\n");
        THROW(EXCEPTION);
    }

    in += readFromBuffer;
    inLength -= readFromBuffer;

    os_memmove(arg->data, in, fieldLength);

    in += fieldLength;
    inLength -= fieldLength;

    *read = readFromBuffer + fieldLength;
    *written = fieldLength;
}
