-- SPDX-License-Identifier: MIT
with Ada.Containers.Vectors;
with Ada.Strings.Unbounded;
with Interfaces;
with MC_Types; use MC_Types;
with MC_FS;
package Pkg_Tar_Framing with SPARK_Mode => Off is
   Max_Entries : constant := 131_072;
   Max_Extension : constant := 1_048_576;
   Max_Extension_Total : constant Counter := 64 * 1024 * 1024;
   type Timestamp is record
      Present : Boolean := False;
      Seconds : Interfaces.Integer_64 := 0;
      Nanoseconds : Natural range 0 .. 999_999_999 := 0;
   end record;
   type Clock_Array is array (1 .. 4) of Timestamp;
   type Name_Array is array (1 .. 4) of Ada.Strings.Unbounded.Unbounded_String;
   type Frame is record
      Header, Body_Start, Size : Counter := 0;
      Type_Flag : Character := ASCII.NUL;
      Clocks : Clock_Array;
      Flags : Ada.Strings.Unbounded.Unbounded_String;
      Names : Name_Array;
   end record;
   type Index is private;
   procedure Scan (File : MC_FS.File; Size, Deadline : Counter;
                   Result : out Index; Status : out Outcome);
   function Count (Value : Index) return Natural;
   function At_Index (Value : Index; Position : Positive) return Frame;
   function Terminator (Value : Index) return Counter;
   -- Structural accounting before the upstream semantic reader. No extraction.
   -- All framing, checksum, size overrides, padding and final zero blocks are
   -- checked. Unknown extensions fail rather than being silently discarded.
   -- Field interpretation and object attributes remain the semantic reader's job.
private
   package Frame_Vectors is new Ada.Containers.Vectors (Positive, Frame);
   type Index is record
      Frames : Frame_Vectors.Vector;
      End_Offset : Counter := 0;
   end record;
end Pkg_Tar_Framing;
