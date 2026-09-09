-- SPDX-License-Identifier: MIT
with Interfaces;
with MC_Types; use MC_Types;
with MC_Text; with MC_Store; with Pkg_Deb_Container;
package Pkg_Deb_Control with SPARK_Mode => Off is
   Max_Entries : constant := 64;
   Max_Contents : constant Counter := 16 * 1024 * 1024;
   Max_Tar_Bytes : constant Counter := 32 * 1024 * 1024;
   type Entry_Kind is (Regular, Directory);
   type Control_Entry is record
      Name, User_Name, Group_Name : MC_Text.Value;
      Kind : Entry_Kind := Regular;
      Mode, UID, GID : Word := 0;
      Modified_Seconds : Interfaces.Integer_64 := 0;
      Modified_Nanoseconds : Natural range 0 .. 999_999_999 := 0;
      Size : Counter := 0;
      Content : Digest := Zero_Digest;
   end record;
   type Entry_Array is array (Positive range 1 .. Max_Entries) of Control_Entry;
   type Inventory is record
      Original, Archive : Digest := Zero_Digest;
      Count, Control_Index : Natural range 0 .. Max_Entries := 0;
      Total_Contents : Counter := 0;
      Entries : Entry_Array;
   end record;
   procedure Stage (Store : in out MC_Store.Store;
                    Expected : Pkg_Deb_Container.Envelope; Deadline : Counter;
                    Result : out Inventory; Status : out Outcome);
   -- Unprivileged original-control observation and CAS retention only. The
   -- original envelope is independently checked before opening its exact member.
   -- Flat regular control files and an optional root directory are retained.
   -- No extraction, scripts, control-field interpretation, installed DB, or
   -- execution permission. Original archives remain the complete byte record.
   -- libarchive's tar interpretation is not canonical tar/trailing-byte proof.
   -- Unsupported names, links, special entries, ACLs, xattrs and sparse entries
   -- fail; no supported-entry subset is returned for a rejected archive.
   -- Completed CAS objects may remain on failure; they do not publish state.
   -- Requires outer process resource/time limits, including synchronous library
   -- decompression and CAS hashing which cannot be interrupted by this deadline.
end Pkg_Deb_Control;
