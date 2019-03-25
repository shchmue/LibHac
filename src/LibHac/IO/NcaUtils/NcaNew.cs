using System;
using System.IO;

namespace LibHac.IO.NcaUtils
{
    public class NcaNew
    {
        private Keyset Keyset { get; }
        private IStorage BaseStorage { get; }

        public NcaHeaderNew Header { get; }
        public byte[] TitleKey { get; }

        public NcaNew(Keyset keyset, IStorage storage)
        {
            Keyset = keyset;
            Header = new NcaHeaderNew(keyset, storage);

            keyset.TitleKeys.TryGetValue(Header.RightsId.ToArray(), out byte[] titleKey);
            TitleKey = titleKey;
        }

        public byte[] GetDecryptedKey(int index)
        {
            if (index < 0 || index > 3) throw new ArgumentOutOfRangeException(nameof(index));

            int generation = Util.GetMasterKeyRevision(Header.KeyGeneration);
            byte[] keyAreaKey = Keyset.KeyAreaKeys[generation][Header.KeyAreaKeyIndex];

            if (keyAreaKey.IsEmpty())
            {
                string keyName = $"key_area_key_{Keyset.KakNames[Header.KeyAreaKeyIndex]}_{generation:x2}";
                throw new MissingKeyException("Unable to decrypt NCA section.", keyName, KeyType.Common);
            }

            byte[] encryptedKey = Header.GetEncryptedKey(index).ToArray();
            var decryptedKey = new byte[Crypto.Aes128Size];

            Crypto.DecryptEcb(keyAreaKey, encryptedKey, decryptedKey, Crypto.Aes128Size);

            return decryptedKey;
        }

        public byte[] GetDecryptedTitleKey()
        {
            int generation = Util.GetMasterKeyRevision(Header.KeyGeneration);
            byte[] titleKek = Keyset.TitleKeks[generation];

            if (!Keyset.TitleKeys.TryGetValue(Header.RightsId.ToArray(), out byte[] encryptedKey))
            {
                throw new MissingKeyException("Missing NCA title key.", Header.RightsId.ToHexString(), KeyType.Title);
            }

            if (titleKek.IsEmpty())
            {
                string keyName = $"titlekek_{generation:x2}";
                throw new MissingKeyException("Unable to decrypt title key.", keyName, KeyType.Common);
            }

            var decryptedKey = new byte[Crypto.Aes128Size];

            Crypto.DecryptEcb(titleKek, encryptedKey, decryptedKey, Crypto.Aes128Size);

            return decryptedKey;
        }

        private IStorage OpenEncryptedStorage(int index)
        {
            if (!Header.IsSectionEnabled(index)) throw new ArgumentOutOfRangeException(nameof(index), "Section is empty");

            long offset = Header.GetSectionStartOffset(index);
            long size = Header.GetSectionSize(index);

            if (!Util.IsSubRange(offset, size, BaseStorage.GetSize()))
            {
                throw new InvalidDataException(
                    $"Section offset (0x{offset:x}) and length (0x{size:x}) fall outside the total NCA length (0x{BaseStorage.GetSize():x}).");
            }

            return BaseStorage.Slice(offset, size);
        }

        //private IStorage OpenDecryptedStorage(IStorage baseStorage, int index)
        //{
        //    NcaFsHeaderNew header = Header.GetFsHeader(index);

        //    switch (header.EncryptionType)
        //    {
        //        case NcaEncryptionType.None:
        //            return baseStorage;
        //        case NcaEncryptionType.XTS:
        //            return OpenAesXtsStorage(baseStorage, index);
        //        case NcaEncryptionType.AesCtr:
        //            return new CachedStorage(new Aes128CtrStorage(baseStorage, DecryptedKeys[2], sect.Offset, sect.Header.Ctr, true), 0x4000, 4, true);
        //        case NcaEncryptionType.AesCtrEx:
        //            BktrPatchInfo info = sect.Header.BktrInfo;

        //            long bktrOffset = info.RelocationHeader.Offset;
        //            long bktrSize = sect.Size - bktrOffset;
        //            long dataSize = info.RelocationHeader.Offset;

        //            IStorage bucketTreeHeader = new MemoryStorage(sect.Header.BktrInfo.EncryptionHeader.Header);
        //            IStorage bucketTreeData = new CachedStorage(new Aes128CtrStorage(baseStorage.Slice(bktrOffset, bktrSize), DecryptedKeys[2], bktrOffset + sect.Offset, sect.Header.Ctr, true), 4, true);

        //            IStorage encryptionBucketTreeData = bucketTreeData.Slice(info.EncryptionHeader.Offset - bktrOffset);
        //            IStorage decStorage = new Aes128CtrExStorage(baseStorage.Slice(0, dataSize), bucketTreeHeader, encryptionBucketTreeData, DecryptedKeys[2], sect.Offset, sect.Header.Ctr, true);
        //            decStorage = new CachedStorage(decStorage, 0x4000, 4, true);

        //            return new ConcatenationStorage(new[] { decStorage, bucketTreeData }, true);
        //        default:
        //            throw new ArgumentOutOfRangeException();
        //    }
        //}

        //private IStorage OpenAesXtsStorage(IStorage baseStorage, int index)
        //{
        //    throw new NotImplementedException("NCA sections using XTS are not supported yet.");
        //}

        //private IStorage OpenAesCtrStorage(IStorage baseStorage, int index)
        //{
        //    NcaFsHeaderNew fsHeader = Header.GetFsHeader(index);

        //    return new CachedStorage(new Aes128CtrStorage(baseStorage, DecryptedKeys[2], Header.GetSectionStartOffset(index), sect.Header.Ctr, true), 0x4000, 4, true);
        //}

        //private IStorage OpenAesCtrExStorage(IStorage baseStorage, int index)
        //{
        //    throw new NotImplementedException("NCA sections using XTS are not supported yet.");
        //}
    }
}
