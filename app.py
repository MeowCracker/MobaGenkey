from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse, HTMLResponse
import os
import zipfile
from io import BytesIO

app = FastAPI()

VariantBase64Table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
VariantBase64Dict = {i: VariantBase64Table[i] for i in range(len(VariantBase64Table))}
VariantBase64ReverseDict = {
    VariantBase64Table[i]: i for i in range(len(VariantBase64Table))
}


def VariantBase64Encode(bs: bytes):
    result = b""
    blocks_count, left_bytes = divmod(len(bs), 3)

    for i in range(blocks_count):
        coding_int = int.from_bytes(bs[3 * i : 3 * i + 3], "little")
        block = VariantBase64Dict[coding_int & 0x3F]
        block += VariantBase64Dict[(coding_int >> 6) & 0x3F]
        block += VariantBase64Dict[(coding_int >> 12) & 0x3F]
        block += VariantBase64Dict[(coding_int >> 18) & 0x3F]
        result += block.encode()

    if left_bytes == 0:
        return result
    elif left_bytes == 1:
        coding_int = int.from_bytes(bs[3 * blocks_count :], "little")
        block = VariantBase64Dict[coding_int & 0x3F]
        block += VariantBase64Dict[(coding_int >> 6) & 0x3F]
        result += block.encode()
        return result
    else:
        coding_int = int.from_bytes(bs[3 * blocks_count :], "little")
        block = VariantBase64Dict[coding_int & 0x3F]
        block += VariantBase64Dict[(coding_int >> 6) & 0x3F]
        block += VariantBase64Dict[(coding_int >> 12) & 0x3F]
        result += block.encode()
        return result


def VariantBase64Decode(s: str):
    result = b""
    blocks_count, left_bytes = divmod(len(s), 4)

    for i in range(blocks_count):
        block = VariantBase64ReverseDict[s[4 * i]]
        block += VariantBase64ReverseDict[s[4 * i + 1]] << 6
        block += VariantBase64ReverseDict[s[4 * i + 2]] << 12
        block += VariantBase64ReverseDict[s[4 * i + 3]] << 18
        result += block.to_bytes(3, "little")

    if left_bytes == 0:
        return result
    elif left_bytes == 2:
        block = VariantBase64ReverseDict[s[4 * blocks_count]]
        block += VariantBase64ReverseDict[s[4 * blocks_count + 1]] << 6
        result += block.to_bytes(1, "little")
        return result
    elif left_bytes == 3:
        block = VariantBase64ReverseDict[s[4 * blocks_count]]
        block += VariantBase64ReverseDict[s[4 * blocks_count + 1]] << 6
        block += VariantBase64ReverseDict[s[4 * blocks_count + 2]] << 12
        result += block.to_bytes(2, "little")
        return result
    else:
        raise ValueError("Invalid encoding.")


def EncryptBytes(key: int, bs: bytes):
    result = bytearray()
    for i in range(len(bs)):
        result.append(bs[i] ^ ((key >> 8) & 0xFF))
        key = result[-1] & key | 0x482D
    return bytes(result)


def DecryptBytes(key: int, bs: bytes):
    result = bytearray()
    for i in range(len(bs)):
        result.append(bs[i] ^ ((key >> 8) & 0xFF))
        key = bs[i] & key | 0x482D
    return bytes(result)


class LicenseType:
    Professional = 1
    Educational = 3
    Persional = 4


class LicenseType:
    Professional = 1
    Educational = 3
    Persional = 4


def generate_license_bytes(
    Type: LicenseType, Count: int, UserName: str, MajorVersion: int, MinorVersion: int
):
    assert Count >= 0
    LicenseString = f"{Type}#{UserName}|{MajorVersion}{MinorVersion}#{Count}#{MajorVersion}3{MinorVersion}6{MinorVersion}#0#0#0#"
    EncodedLicenseString = VariantBase64Encode(
        EncryptBytes(0x787, LicenseString.encode())
    ).decode()
    FileName = EncodedLicenseString.replace("/", "").replace("\\", "")

    # 使用内存文件
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr("Pro.key", EncodedLicenseString)

    zip_buffer.seek(0)
    return (FileName, zip_buffer)


@app.get("/api/generate")
async def generate_license(
    name: str = Query(..., min_length=1),
    ver: str = Query(..., regex=r"^\d+\.\d+$"),
    count: int = Query(1, ge=1),
):
    try:
        MajorVersion, MinorVersion = map(int, ver.split(".")[:2])
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid version format")

    try:
        filename, file_data = generate_license_bytes(
            LicenseType.Professional, count, name, MajorVersion, MinorVersion
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return StreamingResponse(
        content=file_data,
        media_type="application/zip",
        headers={
            "Content-Disposition": f"attachment; filename=Custom.mxtpro",
            "Content-Type": "application/zip",
        },
    )


@app.get("/", response_class=HTMLResponse)
async def index():
    return FileResponse("templates/index.html")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
