/*
* RC6
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_RC6_H__
#define BOTAN_RC6_H__

#include <botan/block_cipher.h>

namespace Botan {

/**
* RC6, Ron Rivest's AES candidate
*/
class BOTAN_DLL RC6 : public BlockCipher_Fixed_Block_Size<16>
   {
   public:
      void encrypt_n(const byte in[], byte out[], size_t blocks) const;
      void decrypt_n(const byte in[], byte out[], size_t blocks) const;

      void clear() { zeroise(S); }
      std::string name() const { return "RC6"; }
      BlockCipher* clone() const { return new RC6; }

      RC6() : BlockCipher_Fixed_Block_Size(1, 32), S(44) {}
   private:
      void key_schedule(const byte[], size_t);

      SecureVector<u32bit> S;
   };

}

#endif
