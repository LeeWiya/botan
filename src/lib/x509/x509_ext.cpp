/*
* X.509 Certificate Extensions
* (C) 1999-2010,2012 Jack Lloyd
* (C) 2016 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/x509_ext.h>
#include <botan/x509cert.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/oids.h>
#include <botan/charset.h>
#include <botan/hash.h>
#include <botan/internal/bit_ops.h>
#include <algorithm>
#include <sstream>

namespace Botan {

/*
* List of X.509 Certificate Extensions
*/
std::unique_ptr<Certificate_Extension>
Extensions::decode_extension_object(const OID& oid,
                                    bool critical,
                                    const std::vector<uint8_t>& body)
   {

   if(oid_str == "2.5.29.20") return "X509v3.CRLNumber";
   if(oid_str == "2.5.29.21") return "X509v3.ReasonCode";
   if(oid_str == "2.5.29.23") return "X509v3.HoldInstructionCode";
   if(oid_str == "2.5.29.24") return "X509v3.InvalidityDate";
   if(oid_str == "2.5.29.30") return "X509v3.NameConstraints";
   if(oid_str == "2.5.29.31") return "X509v3.CRLDistributionPoints";
   if(oid_str == "2.5.29.32") return "X509v3.CertificatePolicies";
   if(oid_str == "2.5.29.32.0") return "X509v3.AnyPolicy";
   if(oid_str == "2.5.29.36") return "X509v3.PolicyConstraints";
   if(oid_str == "2.5.4.10") return "X520.Organization";
   if(oid_str == "2.5.4.11") return "X520.OrganizationalUnit";
   if(oid_str == "2.5.4.12") return "X520.Title";
   if(oid_str == "2.5.4.3") return "X520.CommonName";
   if(oid_str == "2.5.4.4") return "X520.Surname";
   if(oid_str == "2.5.4.42") return "X520.GivenName";
   if(oid_str == "2.5.4.43") return "X520.Initials";
   if(oid_str == "2.5.4.44") return "X520.GenerationalQualifier";
   if(oid_str == "2.5.4.46") return "X520.DNQualifier";
   if(oid_str == "2.5.4.5") return "X520.SerialNumber";
   if(oid_str == "2.5.4.6") return "X520.Country";
   if(oid_str == "2.5.4.65") return "X520.Pseudonym";
   if(oid_str == "2.5.4.7") return "X520.Locality";
   if(oid_str == "2.5.4.8") return "X520.State";


#define X509_EXTENSION(NAME, TYPE) \
   if(oid == OIDS::lookup(NAME)) { return new Cert_Extension::TYPE(); }

   if(oid_str == "2.5.29.15") return "X509v3.KeyUsage";
   X509_EXTENSION("X509v3.KeyUsage", Key_Usage);
   if(oid_str == "2.5.29.19") return "X509v3.BasicConstraints";
   X509_EXTENSION("X509v3.BasicConstraints", Basic_Constraints);
   if(oid_str == "2.5.29.14") return "X509v3.SubjectKeyIdentifier";
   X509_EXTENSION("X509v3.SubjectKeyIdentifier", Subject_Key_ID);
   if(oid_str == "2.5.29.35") return "X509v3.AuthorityKeyIdentifier";
   X509_EXTENSION("X509v3.AuthorityKeyIdentifier", Authority_Key_ID);
   if(oid_str == "2.5.29.37") return "X509v3.ExtendedKeyUsage";
   X509_EXTENSION("X509v3.ExtendedKeyUsage", Extended_Key_Usage);
   if(oid_str == "2.5.29.17") return "X509v3.SubjectAlternativeName";
   X509_EXTENSION("X509v3.IssuerAlternativeName", Issuer_Alternative_Name);
   if(oid_str == "2.5.29.18") return "X509v3.IssuerAlternativeName";
   X509_EXTENSION("X509v3.SubjectAlternativeName", Subject_Alternative_Name);
   X509_EXTENSION("X509v3.NameConstraints", Name_Constraints);
   X509_EXTENSION("X509v3.CertificatePolicies", Certificate_Policies);
   X509_EXTENSION("X509v3.CRLDistributionPoints", CRL_Distribution_Points);
   X509_EXTENSION("PKIX.AuthorityInformationAccess", Authority_Information_Access);
   X509_EXTENSION("X509v3.CRLNumber", CRL_Number);
   X509_EXTENSION("X509v3.ReasonCode", CRL_ReasonCode);

   return new Cert_Extension::Unknown_Extension(oid, critical);
   }

/*
* Extensions Copy Constructor
*/
Extensions::Extensions(const Extensions& extensions) : ASN1_Object()
   {
   *this = extensions;
   }

/*
* Extensions Assignment Operator
*/
Extensions& Extensions::operator=(const Extensions& other)
   {
   m_extensions.clear();

   for(size_t i = 0; i != other.m_extensions.size(); ++i)
      m_extensions.push_back(
         std::make_pair(std::unique_ptr<Certificate_Extension>(other.m_extensions[i].first->copy()),
                        other.m_extensions[i].second));

   m_extensions_raw = other.m_extensions_raw;

   return (*this);
   }

/*
* Validate the extension (the default implementation is a NOP)
*/
void Certificate_Extension::validate(const X509_Certificate&, const X509_Certificate&,
      const std::vector<std::shared_ptr<const X509_Certificate>>&,
      std::vector<std::set<Certificate_Status_Code>>&,
      size_t)
   {
   }

void Extensions::add(Certificate_Extension* extn, bool critical)
   {
   // sanity check: we don't want to have the same extension more than once
   if(m_extensions_info.count(extn->oid_of()) > 0)
      throw Invalid_Argument(extn->oid_name() + " extension already present in Extensions::add");

   Extensions_Info info;
   info.m_decoded.reset(extn);
   info.m_critical = critical;
   info.m_value = extn->encode_inner();
   m_extensions_info.emplace(oid, info);
   }

void Extensions::replace(Certificate_Extension* extn, bool critical)
   {
   // Remove it if it existed
   m_extensions_info.erase(extn->oid_of());

   Extensions_Info info;
   info.m_decoded.reset(extn);
   info.m_critical = critical;
   info.m_value = extn->encode_inner();
   m_extensions_info.emplace(oid, info);
   }

std::unique_ptr<Certificate_Extension> Extensions::get(const OID& oid) const
   {
   auto i = m_extensions_info.info(oid);
   if(i != m_extensions_info.end())
      {
      return m
      }
   
   for(auto& ext : m_extensions)
      {
      if(ext.first->oid_of() == oid)
         {
         return std::unique_ptr<Certificate_Extension>(ext.first->copy());
         }
      }

   return nullptr;
   }

std::vector<std::pair<std::unique_ptr<Certificate_Extension>, bool>> Extensions::extensions() const
   {
   std::vector<std::pair<std::unique_ptr<Certificate_Extension>, bool>> exts;
   for(auto& ext : m_extension_info)
      {
      exts.push_back(std::make_pair(std::unique_ptr<Certificate_Extension>(ext.first->copy()), ext.second));
      }
   return exts;
   }

std::map<OID, std::pair<std::vector<uint8_t>, bool>> Extensions::extensions_raw() const
   {
   return m_extensions_raw;
   }

/*
* Encode an Extensions list
*/
void Extensions::encode_into(DER_Encoder& to_object) const
   {
   // encode any known extensions
   for(size_t i = 0; i != m_extensions.size(); ++i)
      {
      const Certificate_Extension* ext = m_extensions[i].first.get();
      const bool is_critical = m_extensions[i].second;

      const bool should_encode = ext->should_encode();

      if(should_encode)
         {
         to_object.start_cons(SEQUENCE)
               .encode(ext->oid_of())
               .encode_optional(is_critical, false)
               .encode(ext->encode_inner(), OCTET_STRING)
            .end_cons();
         }
      }

   // encode any unknown extensions
   for(const auto& ext_raw : m_extensions_raw)
      {
      const bool is_critical = ext_raw.second.second;
      const OID oid = ext_raw.first;
      const std::vector<uint8_t> value = ext_raw.second.first;

      auto pos = std::find_if(std::begin(m_extensions), std::end(m_extensions),
            [&oid](const std::pair<std::unique_ptr<Certificate_Extension>, bool>& ext) -> bool
            {
            return ext.first->oid_of() == oid;
            });

      if(pos == std::end(m_extensions))
         {
         // not found in m_extensions, must be unknown
         to_object.start_cons(SEQUENCE)
               .encode(oid)
               .encode_optional(is_critical, false)
               .encode(value, OCTET_STRING)
            .end_cons();
         }
      }
   }

/*
* Decode a list of Extensions
*/
void Extensions::decode_from(BER_Decoder& from_source)
   {
   m_extension_oids.clear();
   m_extension_info.clear();

   BER_Decoder sequence = from_source.start_cons(SEQUENCE);

   while(sequence.more_items())
      {
      OID oid;
      Extension_Info info;

      sequence.start_cons(SEQUENCE)
         .decode(oid)
         .decode_optional(info.m_critical, BOOLEAN, UNIVERSAL, false)
         .decode(info.m_value, OCTET_STRING)
         .verify_end()
      .end_cons();

      m_extension_oids.push_back(oid);
      m_extensions_info.emplace(oid, info);
      }
   sequence.verify_end();
   }

/*
* Write the extensions to an info store
*/
void Extensions::contents_to(Data_Store& subject_info,
                             Data_Store& issuer_info) const
   {
   for(auto&& m_extn_info : m_extensions_info)
      {
      m_extensions[i].first->contents_to(subject_info, issuer_info);
      subject_info.add(m_extensions[i].first->oid_name() + ".is_critical", (m_extensions[i].second ? 1 : 0));
      }
   }


namespace Cert_Extension {

/*
* Checked accessor for the path_limit member
*/
size_t Basic_Constraints::get_path_limit() const
   {
   if(!m_is_ca)
      throw Invalid_State("Basic_Constraints::get_path_limit: Not a CA");
   return m_path_limit;
   }

/*
* Encode the extension
*/
std::vector<uint8_t> Basic_Constraints::encode_inner() const
   {
   return DER_Encoder()
      .start_cons(SEQUENCE)
      .encode_if(m_is_ca,
                 DER_Encoder()
                    .encode(m_is_ca)
                    .encode_optional(m_path_limit, NO_CERT_PATH_LIMIT)
         )
      .end_cons()
   .get_contents_unlocked();
   }

/*
* Decode the extension
*/
void Basic_Constraints::decode_inner(const std::vector<uint8_t>& in)
   {
   BER_Decoder(in)
      .start_cons(SEQUENCE)
         .decode_optional(m_is_ca, BOOLEAN, UNIVERSAL, false)
         .decode_optional(m_path_limit, INTEGER, UNIVERSAL, NO_CERT_PATH_LIMIT)
         .verify_end()
      .end_cons();

   if(m_is_ca == false)
      m_path_limit = 0;
   }

/*
* Return a textual representation
*/
void Basic_Constraints::contents_to(Data_Store& subject, Data_Store&) const
   {
   subject.add("X509v3.BasicConstraints.is_ca", (m_is_ca ? 1 : 0));
   subject.add("X509v3.BasicConstraints.path_constraint", static_cast<uint32_t>(m_path_limit));
   }

/*
* Encode the extension
*/
std::vector<uint8_t> Key_Usage::encode_inner() const
   {
   if(m_constraints == NO_CONSTRAINTS)
      throw Encoding_Error("Cannot encode zero usage constraints");

   const size_t unused_bits = low_bit(m_constraints) - 1;

   std::vector<uint8_t> der;
   der.push_back(BIT_STRING);
   der.push_back(2 + ((unused_bits < 8) ? 1 : 0));
   der.push_back(unused_bits % 8);
   der.push_back((m_constraints >> 8) & 0xFF);
   if(m_constraints & 0xFF)
      der.push_back(m_constraints & 0xFF);

   return der;
   }

/*
* Decode the extension
*/
void Key_Usage::decode_inner(const std::vector<uint8_t>& in)
   {
   BER_Decoder ber(in);

   BER_Object obj = ber.get_next_object();

   if(obj.type_tag != BIT_STRING || obj.class_tag != UNIVERSAL)
      throw BER_Bad_Tag("Bad tag for usage constraint",
                        obj.type_tag, obj.class_tag);

   if(obj.value.size() != 2 && obj.value.size() != 3)
      throw BER_Decoding_Error("Bad size for BITSTRING in usage constraint");

   if(obj.value[0] >= 8)
      throw BER_Decoding_Error("Invalid unused bits in usage constraint");

   obj.value[obj.value.size()-1] &= (0xFF << obj.value[0]);

   uint16_t usage = 0;
   for(size_t i = 1; i != obj.value.size(); ++i)
      {
      usage = (obj.value[i] << 8*(sizeof(usage)-i)) | usage;
      }

   m_constraints = Key_Constraints(usage);
   }

/*
* Return a textual representation
*/
void Key_Usage::contents_to(Data_Store& subject, Data_Store&) const
   {
   subject.add("X509v3.KeyUsage", m_constraints);
   }

/*
* Encode the extension
*/
std::vector<uint8_t> Subject_Key_ID::encode_inner() const
   {
   return DER_Encoder().encode(m_key_id, OCTET_STRING).get_contents_unlocked();
   }

/*
* Decode the extension
*/
void Subject_Key_ID::decode_inner(const std::vector<uint8_t>& in)
   {
   BER_Decoder(in).decode(m_key_id, OCTET_STRING).verify_end();
   }

/*
* Return a textual representation
*/
void Subject_Key_ID::contents_to(Data_Store& subject, Data_Store&) const
   {
   subject.add("X509v3.SubjectKeyIdentifier", m_key_id);
   }

/*
* Subject_Key_ID Constructor
*/
Subject_Key_ID::Subject_Key_ID(const std::vector<uint8_t>& pub_key, const std::string& hash_name)
   {
   std::unique_ptr<HashFunction> hash(HashFunction::create_or_throw(hash_name));

   m_key_id.resize(hash->output_length());

   hash->update(pub_key);
   hash->final(m_key_id.data());
   }

/*
* Encode the extension
*/
std::vector<uint8_t> Authority_Key_ID::encode_inner() const
   {
   return DER_Encoder()
         .start_cons(SEQUENCE)
            .encode(m_key_id, OCTET_STRING, ASN1_Tag(0), CONTEXT_SPECIFIC)
         .end_cons()
      .get_contents_unlocked();
   }

/*
* Decode the extension
*/
void Authority_Key_ID::decode_inner(const std::vector<uint8_t>& in)
   {
   BER_Decoder(in)
      .start_cons(SEQUENCE)
      .decode_optional_string(m_key_id, OCTET_STRING, 0);
   }

/*
* Return a textual representation
*/
void Authority_Key_ID::contents_to(Data_Store&, Data_Store& issuer) const
   {
   if(m_key_id.size())
      issuer.add("X509v3.AuthorityKeyIdentifier", m_key_id);
   }

/*
* Encode the extension
*/
std::vector<uint8_t> Subject_Alternative_Name::encode_inner() const
   {
   return DER_Encoder().encode(m_alt_name).get_contents_unlocked();
   }

/*
* Encode the extension
*/
std::vector<uint8_t> Issuer_Alternative_Name::encode_inner() const
   {
   return DER_Encoder().encode(m_alt_name).get_contents_unlocked();
   }

/*
* Decode the extension
*/
void Subject_Alternative_Name::decode_inner(const std::vector<uint8_t>& in)
   {
   BER_Decoder(in).decode(m_alt_name);
   }

/*
* Decode the extension
*/
void Issuer_Alternative_Name::decode_inner(const std::vector<uint8_t>& in)
   {
   BER_Decoder(in).decode(m_alt_name);
   }

/*
* Return a textual representation
*/
void Subject_Alternative_Name::contents_to(Data_Store& subject_info,
                                           Data_Store&) const
   {
   std::multimap<std::string, std::string> contents =
      get_alt_name().contents();

   subject_info.add(contents);
   }

/*
* Return a textual representation
*/
void Issuer_Alternative_Name::contents_to(Data_Store&, Data_Store& issuer_info) const
   {
   std::multimap<std::string, std::string> contents =
      get_alt_name().contents();

   issuer_info.add(contents);
   }


/*
* Encode the extension
*/
std::vector<uint8_t> Extended_Key_Usage::encode_inner() const
   {
   return DER_Encoder()
      .start_cons(SEQUENCE)
         .encode_list(m_oids)
      .end_cons()
   .get_contents_unlocked();
   }

/*
* Decode the extension
*/
void Extended_Key_Usage::decode_inner(const std::vector<uint8_t>& in)
   {
   BER_Decoder(in).decode_list(m_oids);
   }

/*
* Return a textual representation
*/
void Extended_Key_Usage::contents_to(Data_Store& subject, Data_Store&) const
   {
   for(size_t i = 0; i != m_oids.size(); ++i)
      subject.add("X509v3.ExtendedKeyUsage", m_oids[i].as_string());
   }

/*
* Encode the extension
*/
std::vector<uint8_t> Name_Constraints::encode_inner() const
   {
   throw Not_Implemented("Name_Constraints encoding");
   }


/*
* Decode the extension
*/
void Name_Constraints::decode_inner(const std::vector<uint8_t>& in)
   {
   std::vector<GeneralSubtree> permit, exclude;
   BER_Decoder ber(in);
   BER_Decoder ext = ber.start_cons(SEQUENCE);
   BER_Object per = ext.get_next_object();

   ext.push_back(per);
   if(per.type_tag == 0 && per.class_tag == ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC))
      {
      ext.decode_list(permit,ASN1_Tag(0),ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC));
      if(permit.empty())
         throw Encoding_Error("Empty Name Contraint list");
      }

   BER_Object exc = ext.get_next_object();
   ext.push_back(exc);
   if(per.type_tag == 1 && per.class_tag == ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC))
      {
      ext.decode_list(exclude,ASN1_Tag(1),ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC));
      if(exclude.empty())
         throw Encoding_Error("Empty Name Contraint list");
      }

   ext.end_cons();

   if(permit.empty() && exclude.empty())
      throw Encoding_Error("Empty Name Contraint extension");

   m_name_constraints = NameConstraints(std::move(permit),std::move(exclude));
   }

/*
* Return a textual representation
*/
void Name_Constraints::contents_to(Data_Store& subject, Data_Store&) const
   {
   std::stringstream ss;

   for(const GeneralSubtree& gs: m_name_constraints.permitted())
      {
      ss << gs;
      subject.add("X509v3.NameConstraints.permitted", ss.str());
      ss.str(std::string());
      }
   for(const GeneralSubtree& gs: m_name_constraints.excluded())
      {
      ss << gs;
      subject.add("X509v3.NameConstraints.excluded", ss.str());
      ss.str(std::string());
      }
   }

void Name_Constraints::validate(const X509_Certificate& subject, const X509_Certificate& issuer,
      const std::vector<std::shared_ptr<const X509_Certificate>>& cert_path,
      std::vector<std::set<Certificate_Status_Code>>& cert_status,
      size_t pos)
   {
   if(!m_name_constraints.permitted().empty() || !m_name_constraints.excluded().empty())
      {
      if(!subject.is_CA_cert() || !subject.is_critical("X509v3.NameConstraints"))
         cert_status.at(pos).insert(Certificate_Status_Code::NAME_CONSTRAINT_ERROR);

      const bool at_self_signed_root = (pos == cert_path.size() - 1);

      // Check that all subordinate certs pass the name constraint
      for(size_t j = 0; j <= pos; ++j)
         {
         if(pos == j && at_self_signed_root)
            continue;

         bool permitted = m_name_constraints.permitted().empty();
         bool failed = false;

         for(auto c: m_name_constraints.permitted())
            {
            switch(c.base().matches(*cert_path.at(j)))
               {
            case GeneralName::MatchResult::NotFound:
            case GeneralName::MatchResult::All:
               permitted = true;
               break;
            case GeneralName::MatchResult::UnknownType:
               failed = issuer.is_critical("X509v3.NameConstraints");
               permitted = true;
               break;
            default:
               break;
               }
            }

         for(auto c: m_name_constraints.excluded())
            {
            switch(c.base().matches(*cert_path.at(j)))
               {
            case GeneralName::MatchResult::All:
            case GeneralName::MatchResult::Some:
               failed = true;
               break;
            case GeneralName::MatchResult::UnknownType:
               failed = issuer.is_critical("X509v3.NameConstraints");
               break;
            default:
               break;
               }
            }

         if(failed || !permitted)
            {
            cert_status.at(j).insert(Certificate_Status_Code::NAME_CONSTRAINT_ERROR);
            }
         }
      }
   }

namespace {

/*
* A policy specifier
*/
class Policy_Information : public ASN1_Object
   {
   public:
      Policy_Information() {}
      explicit Policy_Information(const OID& oid) : m_oid(oid) {}

      const OID& oid() const { return m_oid; }

      void encode_into(DER_Encoder& codec) const override
         {
         codec.start_cons(SEQUENCE)
            .encode(m_oid)
            .end_cons();
         }

      void decode_from(BER_Decoder& codec) override
         {
         codec.start_cons(SEQUENCE)
            .decode(m_oid)
            .discard_remaining()
            .end_cons();
         }

   private:
      OID m_oid;
   };

}

/*
* Encode the extension
*/
std::vector<uint8_t> Certificate_Policies::encode_inner() const
   {
   std::vector<Policy_Information> policies;

   for(size_t i = 0; i != m_oids.size(); ++i)
      policies.push_back(Policy_Information(m_oids[i]));

   return DER_Encoder()
      .start_cons(SEQUENCE)
         .encode_list(policies)
      .end_cons()
   .get_contents_unlocked();
   }

/*
* Decode the extension
*/
void Certificate_Policies::decode_inner(const std::vector<uint8_t>& in)
   {
   std::vector<Policy_Information> policies;

   BER_Decoder(in).decode_list(policies);

   m_oids.clear();
   for(size_t i = 0; i != policies.size(); ++i)
      m_oids.push_back(policies[i].oid());
   }

/*
* Return a textual representation
*/
void Certificate_Policies::contents_to(Data_Store& info, Data_Store&) const
   {
   for(size_t i = 0; i != m_oids.size(); ++i)
      info.add("X509v3.CertificatePolicies", m_oids[i].as_string());
   }

std::vector<uint8_t> Authority_Information_Access::encode_inner() const
   {
   ASN1_String url(m_ocsp_responder, IA5_STRING);

   return DER_Encoder()
      .start_cons(SEQUENCE)
      .start_cons(SEQUENCE)
      .encode(OIDS::lookup("PKIX.OCSP"))
      .add_object(ASN1_Tag(6), CONTEXT_SPECIFIC, url.iso_8859())
      .end_cons()
      .end_cons().get_contents_unlocked();
   }

void Authority_Information_Access::decode_inner(const std::vector<uint8_t>& in)
   {
   BER_Decoder ber = BER_Decoder(in).start_cons(SEQUENCE);

   while(ber.more_items())
      {
      OID oid;

      BER_Decoder info = ber.start_cons(SEQUENCE);

      info.decode(oid);

      if(oid == OIDS::lookup("PKIX.OCSP"))
         {
         BER_Object name = info.get_next_object();

         if(name.type_tag == 6 && name.class_tag == CONTEXT_SPECIFIC)
            {
            m_ocsp_responder = Charset::transcode(ASN1::to_string(name),
                                                  LATIN1_CHARSET,
                                                  LOCAL_CHARSET);
            }

         }
      }
   }

void Authority_Information_Access::contents_to(Data_Store& subject, Data_Store&) const
   {
   if(!m_ocsp_responder.empty())
      subject.add("OCSP.responder", m_ocsp_responder);
   }

/*
* Checked accessor for the crl_number member
*/
size_t CRL_Number::get_crl_number() const
   {
   if(!m_has_value)
      throw Invalid_State("CRL_Number::get_crl_number: Not set");
   return m_crl_number;
   }

/*
* Copy a CRL_Number extension
*/
CRL_Number* CRL_Number::copy() const
   {
   if(!m_has_value)
      throw Invalid_State("CRL_Number::copy: Not set");
   return new CRL_Number(m_crl_number);
   }

/*
* Encode the extension
*/
std::vector<uint8_t> CRL_Number::encode_inner() const
   {
   return DER_Encoder().encode(m_crl_number).get_contents_unlocked();
   }

/*
* Decode the extension
*/
void CRL_Number::decode_inner(const std::vector<uint8_t>& in)
   {
   BER_Decoder(in).decode(m_crl_number);
   }

/*
* Return a textual representation
*/
void CRL_Number::contents_to(Data_Store& info, Data_Store&) const
   {
   info.add("X509v3.CRLNumber", static_cast<uint32_t>(m_crl_number));
   }

/*
* Encode the extension
*/
std::vector<uint8_t> CRL_ReasonCode::encode_inner() const
   {
   return DER_Encoder()
      .encode(static_cast<size_t>(m_reason), ENUMERATED, UNIVERSAL)
   .get_contents_unlocked();
   }

/*
* Decode the extension
*/
void CRL_ReasonCode::decode_inner(const std::vector<uint8_t>& in)
   {
   size_t reason_code = 0;
   BER_Decoder(in).decode(reason_code, ENUMERATED, UNIVERSAL);
   m_reason = static_cast<CRL_Code>(reason_code);
   }

/*
* Return a textual representation
*/
void CRL_ReasonCode::contents_to(Data_Store& info, Data_Store&) const
   {
   info.add("X509v3.CRLReasonCode", m_reason);
   }

std::vector<uint8_t> CRL_Distribution_Points::encode_inner() const
   {
   throw Not_Implemented("CRL_Distribution_Points encoding");
   }

void CRL_Distribution_Points::decode_inner(const std::vector<uint8_t>& buf)
   {
   BER_Decoder(buf)
      .decode_list(m_distribution_points)
      .verify_end();

   for(size_t i = 0; i != m_distribution_points.size(); ++i)
      {
      auto point = m_distribution_points[i].point().contents();

      auto uris = point.equal_range("URI");
      for(auto uri = uris.first; uri != uris.second; ++uri)
         m_crl_distribution_urls.push_back(uri->second);
      }
   }

void CRL_Distribution_Points::contents_to(Data_Store& subject, Data_Store&) const
   {
   for(const std::string& crl_url : m_crl_distribution_urls)
      subject.add("CRL.DistributionPoint", crl_url);
   }

void CRL_Distribution_Points::Distribution_Point::encode_into(class DER_Encoder&) const
   {
   throw Not_Implemented("CRL_Distribution_Points encoding");
   }

void CRL_Distribution_Points::Distribution_Point::decode_from(class BER_Decoder& ber)
   {
   ber.start_cons(SEQUENCE)
      .start_cons(ASN1_Tag(0), CONTEXT_SPECIFIC)
        .decode_optional_implicit(m_point, ASN1_Tag(0),
                                  ASN1_Tag(CONTEXT_SPECIFIC | CONSTRUCTED),
                                  SEQUENCE, CONSTRUCTED)
      .end_cons().end_cons();
   }

std::vector<uint8_t> Unknown_Extension::encode_inner() const
   {
   return m_bytes;
   }

void Unknown_Extension::decode_inner(const std::vector<uint8_t>& bytes)
   {
   // Just treat as an opaque blob at this level
   m_bytes = bytes;
   }

void Unknown_Extension::contents_to(Data_Store&, Data_Store&) const
   {
   // No information store
   }

}

}
