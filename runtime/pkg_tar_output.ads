-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Finalization;
with MC_Types; use MC_Types;
with Pkg_Tar_Framing;
package Pkg_Tar_Output with SPARK_Mode => Off is
   Max_Header : constant := Pkg_Tar_Framing.Max_Extension + 1_024;
   type Header is new Ada.Finalization.Limited_Controlled with private;
   procedure Start (Value : in out Header; Path : String; Mode, UID, GID : Word;
      Size : Counter; Clocks : Pkg_Tar_Framing.Clock_Array; Status : out Outcome);
   procedure Add_Extension (Value : in out Header; Key : String; Data : Bytes; Status : out Outcome);
   procedure Add_Xattr (Value : in out Header; Name : String; Data : Bytes; Status : out Outcome);
   procedure Finish (Value : in out Header; Output : out Bytes; Used : out Natural; Status : out Outcome);
   procedure Clear (Value : in out Header);
   -- Emits one regular-file PAX/header prefix, without content, body padding or
   -- archive terminators. The caller must append exactly Size bytes and padding.
   -- Names are canonical root-relative bytes; BINARY prevents locale conversion.
   -- Full numeric permissions/owners and signed nanosecond clocks are encoded
   -- without depending on upstream writer timestamp conversion. Mtime is required.
   -- Add_Xattr encodes a raw name/value as LIBARCHIVE.xattr using percent-encoded
   -- names and unpadded base64. Extensions retain already-encoded records. Keys are
   -- unique and sorted; builtin path/size/owner/clock fields cannot be overridden.
   -- This codec does not interpret ACL/flag/xattr effects or authorize their use.
   -- Finish consumes the builder. Any failure clears state and returned bytes.
private
   type Data;
   type Data_Access is access Data;
   type Header is new Ada.Finalization.Limited_Controlled with record
      State : Data_Access;
   end record;
   overriding procedure Finalize (Value : in out Header);
end Pkg_Tar_Output;
