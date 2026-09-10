-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_FS;
package MC_Atomic with SPARK_Mode => Off is
   procedure Write(R : MC_FS.Root; Path : String; Data : Bytes;
                   Must_Be_New : Boolean; Status : out Outcome);
   procedure Read(R : MC_FS.Root; Path : String; Data : out Bytes;
                  Used : out Natural; Status : out Outcome);
   -- Caller holds resource lock. Write includes file+parent fsync. An error after
   -- rename is Indeterminate, requiring read-back; never retry a semantic effect.
end MC_Atomic;
