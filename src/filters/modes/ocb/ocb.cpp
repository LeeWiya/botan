/*
* OCB Mode
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/ocb.h>
#include <botan/cmac.h>
#include <botan/internal/xor_buf.h>
#include <botan/internal/bit_ops.h>
#include <algorithm>

#include <botan/hex.h>
#include <iostream>

namespace Botan {

// Has to be in Botan namespace so unique_ptr can reference it
class L_computer
   {
   public:
      L_computer(const BlockCipher& cipher)
         {
         m_L_star.resize(cipher.block_size());
         cipher.encrypt(m_L_star);
         m_L_dollar = poly_double(star());
         m_L.push_back(poly_double(dollar()));
         }

      const secure_vector<byte>& star() const { return m_L_star; }

      const secure_vector<byte>& dollar() const { return m_L_dollar; }

      const secure_vector<byte>& operator()(size_t i) const { return get(i); }

      const secure_vector<byte>& get(size_t i) const
         {
         while(m_L.size() <= i)
            m_L.push_back(poly_double(m_L.back()));

         return m_L.at(i);
         }

   private:
      secure_vector<byte> poly_double(const secure_vector<byte>& in) const
         {
         return CMAC::poly_double(in, 0x87);
         }

      secure_vector<byte> m_L_dollar, m_L_star;
      mutable std::vector<secure_vector<byte>> m_L;
   };

#if 0
class Nonce_State
   {
   public:
      secure_vector<byte> update_nonce(const byte nonce[], size_t nonce_len);

      bool fresh_nonce() { bool b = false; std::swap(b, m_fresh); return b; }
   private:
      secure_vector<byte> m_stretch;
      bool m_fresh = false;
   };
#endif

namespace {

/*
* OCB's HASH
*/
secure_vector<byte> ocb_hash(const L_computer& L,
                             const BlockCipher& cipher,
                             const byte ad[], size_t ad_len)
   {
   const size_t BS = cipher.block_size();

   secure_vector<byte> sum(BS);
   secure_vector<byte> offset(BS);

   secure_vector<byte> buf(BS);

   const size_t ad_blocks = (ad_len / BS);
   const size_t ad_remainder = (ad_len % BS);

   for(size_t i = 0; i != ad_blocks; ++i)
      {
      // this loop could run in parallel
      offset ^= L(ctz(i+1));

      buf = offset;
      xor_buf(&buf[0], &ad[BS*i], BS);

      cipher.encrypt(buf);

      sum ^= buf;
      }

   if(ad_remainder)
      {
      offset ^= L.star();

      buf = offset;
      xor_buf(&buf[0], &ad[BS*ad_blocks], ad_remainder);
      buf[ad_len % BS] ^= 0x80;

      cipher.encrypt(buf);

      sum ^= buf;
      }

   return sum;
   }

}

OCB_Mode::OCB_Mode(BlockCipher* cipher, size_t tag_size, bool decrypting) :
   Buffered_Filter(cipher->parallel_bytes(), decrypting ? tag_size : 0),
   m_cipher(cipher), m_tag_size(tag_size),
   m_ad_hash(BS), m_offset(BS), m_checksum(BS)
   {
   if(m_cipher->block_size() != BS)
      throw std::invalid_argument("OCB requires a 128 bit cipher so cannot be used with " +
                                  m_cipher->name());

   if(m_tag_size != 16) // 64, 96 bits also supported
      throw std::invalid_argument("OCB cannot produce a " + std::to_string(m_tag_size) +
                                  " byte tag");

   }

OCB_Mode::~OCB_Mode() { /* for unique_ptr destructor */ }

bool OCB_Mode::valid_keylength(size_t n) const
   {
   return m_cipher->valid_keylength(n);
   }

std::string OCB_Mode::name() const
   {
   return m_cipher->name() + "/OCB"; // include tag size
   }

void OCB_Mode::set_key(const SymmetricKey& key)
   {
   m_cipher->set_key(key);
   m_L.reset(new L_computer(*m_cipher));
   }

void OCB_Mode::set_nonce(const byte nonce[], size_t nonce_len)
   {
   if(!valid_iv_length(nonce_len))
      throw Invalid_IV_Length(name(), nonce_len);

   byte bottom;
   secure_vector<byte> stretch;

   if(1) // need to recompute stretch (save iv to compare)
      {
      secure_vector<byte> buf(BS);

      const size_t offset = BS - nonce_len;

      copy_mem(&buf[offset], nonce, nonce_len);
      buf[offset-1] = 1;

      bottom = buf[15] & 0x3F;
      buf[15] &= 0xC0;

      m_cipher->encrypt(buf);

      for(size_t i = 0; i != 8; ++i)
         buf.push_back(buf[i] ^ buf[i+1]);

      stretch = buf;
      }

   // now set the offset from stretch and bottom

   const size_t shift_bytes = bottom / 8;
   const size_t shift_bits  = bottom % 8;

   for(size_t i = 0; i != BS; ++i)
      {
      m_offset[i]  = (stretch[i+shift_bytes] << shift_bits);
      m_offset[i] |= (stretch[i+shift_bytes+1] >> (8-shift_bits));
      }
   }

void OCB_Mode::start_msg()
   {
   //BOTAN_ASSERT(m_nonce_state.fresh_nonce(), "Nonce state is fresh");
   }

void OCB_Mode::set_associated_data(const byte ad[], size_t ad_len)
   {
   m_ad_hash = ocb_hash(*m_L, *m_cipher, &ad[0], ad_len);
   }

void OCB_Mode::write(const byte input[], size_t length)
   {
   Buffered_Filter::write(input, length);
   }

void OCB_Mode::end_msg()
   {
   Buffered_Filter::end_msg();
   }

void OCB_Encryption::buffered_block(const byte input[], size_t input_length)
   {
   BOTAN_ASSERT(input_length % BS == 0, "Input length is an even number of blocks");

   const size_t blocks = input_length / BS;

   const size_t par_bytes = m_cipher->parallel_bytes();

   BOTAN_ASSERT(par_bytes % BS == 0, "Cipher is parallel in full blocks");

   const size_t par_blocks = par_bytes / BS;

   const L_computer& L = *m_L; // convenient name

   secure_vector<byte> ctext_buf(par_bytes);
   secure_vector<byte> csum_accum(par_bytes);
   secure_vector<byte> offsets(par_bytes);

   size_t blocks_left = blocks;

   while(blocks_left)
      {
      const size_t to_proc = std::min(blocks_left, par_blocks);
      const size_t proc_bytes = to_proc * BS;

      xor_buf(&csum_accum[0], &input[0], proc_bytes);

      for(size_t i = 0; i != to_proc; ++i)
         {
         m_offset ^= L(ctz(++m_block_index));
         copy_mem(&offsets[BS*i], &m_offset[0], BS);
         }

      copy_mem(&ctext_buf[0], &input[0], proc_bytes);

      ctext_buf ^= offsets;
      m_cipher->encrypt(ctext_buf);
      ctext_buf ^= offsets;

      send(ctext_buf, proc_bytes);

      input += proc_bytes;
      blocks_left -= to_proc;
      }

   // fold into checksum
   for(size_t i = 0; i != csum_accum.size(); ++i)
      m_checksum[i % BS] ^= csum_accum[i];
   }

void OCB_Encryption::buffered_final(const byte input[], size_t input_length)
   {
   if(input_length >= BS)
      {
      const size_t final_blocks = input_length / BS;
      const size_t final_bytes = final_blocks * BS;
      buffered_block(input, final_bytes);
      input += final_bytes;
      input_length -= final_bytes;
      }

   if(input_length)
      {
      BOTAN_ASSERT(input_length < BS, "Only a partial block left");

      xor_buf(&m_checksum[0], &input[0], input_length);
      m_checksum[input_length] ^= 0x80;

      m_offset ^= m_L->star(); // Offset_*

      secure_vector<byte> buf(BS);
      m_cipher->encrypt(m_offset, buf);
      xor_buf(&buf[0], &input[0], input_length);

      send(buf, input_length); // final ciphertext
      }

   // now compute the tag
   secure_vector<byte> mac = m_offset;
   mac ^= m_checksum;
   mac ^= m_L->dollar();

   m_cipher->encrypt(mac);

   mac ^= m_ad_hash;

   send(mac);

   zeroise(m_checksum);
   zeroise(m_offset);
   m_block_index = 0;
   }

void OCB_Decryption::buffered_block(const byte input[], size_t input_length)
   {
   BOTAN_ASSERT(input_length % BS == 0, "Input length is an even number of blocks");

   const size_t blocks = input_length / BS;

   const L_computer& L = *m_L;

   secure_vector<byte> ptext_buf(BS);

   for(size_t i = 0; i != blocks; ++i)
      {
      // could run in parallel

      m_offset ^= L(ctz(++m_block_index));

      ptext_buf = m_offset;
      xor_buf(&ptext_buf[0], &input[BS*i], BS);
      m_cipher->decrypt(ptext_buf);
      ptext_buf ^= m_offset;

      send(ptext_buf);
      m_checksum ^= ptext_buf;
      }
   }

void OCB_Decryption::buffered_final(const byte input[], size_t input_length)
   {
   BOTAN_ASSERT(input_length >= m_tag_size, "We have the tag");

   const byte* included_tag = &input[input_length-m_tag_size];
   input_length -= m_tag_size;

   if(input_length >= BS)
      {
      const size_t final_blocks = input_length / BS;
      const size_t final_bytes = final_blocks * BS;
      buffered_block(input, final_bytes);
      input += final_bytes;
      input_length -= final_bytes;
      }

   if(input_length)
      {
      BOTAN_ASSERT(input_length < BS, "Only a partial block left");

      m_offset ^= m_L->star(); // Offset_*

      secure_vector<byte> buf(BS);
      m_cipher->encrypt(m_offset, buf); // P_*

      xor_buf(&buf[0], &input[0], input_length);

      xor_buf(&m_checksum[0], &buf[0], input_length);
      m_checksum[input_length] ^= 0x80;

      send(buf, input_length); // final plaintext
      }

   // now compute the tag
   secure_vector<byte> mac = m_offset;
   mac ^= m_checksum;
   mac ^= m_L->dollar();

   m_cipher->encrypt(mac);

   mac ^= m_ad_hash;

   zeroise(m_checksum);
   zeroise(m_offset);
   m_block_index = 0;

   if(!same_mem(&mac[0], included_tag, m_tag_size))
      throw Integrity_Failure("OCB tag check failed");
   }

}