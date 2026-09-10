-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types; with MC_Signatures;
package MC_Keys with SPARK_Mode => Off is
   procedure Generate(Private_Directory : String; Public_Key : out MC_Signatures.Public_Key; Status : out Outcome);
   procedure Sign(Private_Directory : String; Message : Bytes;
      Public_Key : out MC_Signatures.Public_Key; Signature : out MC_Signatures.Signature; Status : out Outcome);
   -- Local administrative/offline signing utility. Not a witness observer, a key
   -- distribution system, or a statement that signed facts were physically verified.
   -- Seed is a private regular 0400/0600 file, no argv/env secrets, locked memory,
   -- explicit zeroization. libsodium + OS memory protection are trusted boundaries.
end MC_Keys;
