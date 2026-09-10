-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Finalization;
with MC_Types; use MC_Types;
with MC_Store; with Pkg_Deb_Payload; with Pkg_Conffile_Transition;
package Pkg_Conffile_Observation with SPARK_Mode => Off is
   Max_Bytes : constant := 196_608;
   type Node_Identity is record
      Mount, Inode : Wide := 0;
      Device_Major, Device_Minor, Mode, UID, GID : Word := 0;
   end record;
   type File_Attributes is record
      Node : Node_Identity;
      Links : Word := 0;
      Size : Counter := 0;
      Attributes, Attribute_Mask, Inode_Flags : Wide := 0;
      Accessed, Modified, Changed, Created : Pkg_Deb_Payload.Timestamp;
   end record;
   type Observation is new Ada.Finalization.Limited_Controlled with private;
   procedure Load (Store : MC_Store.Store; Address : Digest; Expected_Path : String;
      Deadline : Counter; Value : in out Observation; Status : out Outcome);
   procedure Clear (Value : in out Observation);
   function Address (Value : Observation) return Digest;
   function Path (Value : Observation) return String;
   function Image (Value : Observation) return Pkg_Conffile_Transition.Image;
   function Attributes (Value : Observation) return File_Attributes;
   function Observer_UID (Value : Observation) return Word;
   function Observer_GID (Value : Observation) return Word;
   function Directory_Count (Value : Observation) return Natural;
   procedure Read_Directory (Value : Observation; Position : Positive;
      Node : out Node_Identity; Status : out Outcome);
   function Missing_Component (Value : Observation) return Natural;
   function Xattr_Count (Value : Observation) return Natural;
   procedure Read_Xattr (Value : Observation; Position : Positive;
      Name : out Pkg_Deb_Payload.Byte_Strings.Bounded_String;
      Data : out Bytes; Used : out Natural; Status : out Outcome);
   -- Durable NIACOBS1 decoder. Rehashes metadata and regular content in the
   -- caller's existing Store, validates all lengths/identities/component counts,
   -- signed clocks, masks, byte-ordering and the exact expected raw path.
   -- No reconstruction, host path read or visibility/liveness/authority claim.
   -- Inline xattrs (including visible raw ACLs) remain exact bytes, distinct
   -- from symbolic archive ACLs. All observed flags and namespace identities
   -- survive; observed inode/ctime/birthtime are not automatically restorable.
   -- Missing_Component is the one-based component index, zero for a regular
   -- file or invalid observation. Cleared Image is Other, not Missing.
   -- Opaque observers, privileged hidden attributes and live root validation
   -- remain the responsibility of independent observation/admission providers.
private
   type Data;
   type Data_Access is access Data;
   type Observation is new Ada.Finalization.Limited_Controlled with record
      State : Data_Access;
   end record;
   overriding procedure Finalize (Value : in out Observation);
end Pkg_Conffile_Observation;
