-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_Signatures;
package MC_Authentic with SPARK_Mode => Off is
   procedure Verify(Domain : String; Data : Bytes; Signature : MC_Signatures.Signature;
                    Key : MC_Signatures.Public_Key; Status : out Outcome);
   -- Signed bytes = u16be(domain length) || domain || data. Caller uses a fixed
   -- protocol domain, never a domain selected from an untrusted packet.
end MC_Authentic;
