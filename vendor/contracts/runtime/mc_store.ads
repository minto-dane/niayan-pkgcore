-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_FS; with MC_SHA256;
package MC_Store with SPARK_Mode => Off is
   Max_Object_Size : constant Counter := 8 * 1024 * 1024 * 1024;
   type Store is limited private;
   type Writer is limited private;
   procedure Initialize (Path : String; S : in out Store; Status : out Outcome);
   -- Explicit bootstrap: private EMPTY directory only. A partial initialization
   -- is retained for diagnosis; Initialize never repairs or resets an old store.
   procedure Open (Path : String; S : in out Store; Status : out Outcome);
   -- Existing store only: missing lock/objects/incoming/pins is corruption. Never
   -- create replacement ownership or recovery state during ordinary Open.
   procedure Put (S : in out Store; Data : Bytes; D : out Digest; Status : out Outcome);
   procedure Import_File (S : in out Store; Input : MC_FS.File; Limit : Counter;
                          D : out Digest; Status : out Outcome);
   procedure Open_Object (S : Store; D : Digest; F : in out MC_FS.File; Status : out Outcome);
   procedure Read_Object (S : Store; D : Digest; Data : out Bytes;
                          Used : out Natural; Status : out Outcome);
   procedure Pin (S : in out Store; ID : Identity; Manifest : Digest; Status : out Outcome);
   procedure Check_Pin (S : Store; ID : Identity; Manifest : Digest; Status : out Outcome);
   procedure Begin_Write(S : in out Store; Expected : Digest; Size : Counter;
                         W : in out Writer; Status : out Outcome);
   procedure Write_Chunk(W : in out Writer; Data : Bytes; Status : out Outcome);
   procedure Finish_Write(S : in out Store; W : in out Writer; Status : out Outcome);
   procedure Abort_Write(W : in out Writer);
   function Native_Reservation (S : Store) return Integer;
   -- Borrowed descriptor of the held writer reservation, or -1 when closed.
   -- Internal FD transfer only: never close, unlock, mutate or retain it beyond
   -- S's lifetime. SCM_RIGHTS shares its OFD; consumers must never LOCK_UN.
   -- This conveys exclusion, not admission or permission to mutate the store.
   procedure Close (S : in out Store);
   -- Local content-addressed storage, not an authorization authority. Every read
   -- rehashes the descriptor before consumption. Pins are immutable, never GC'd.
private
   type Writer is limited record
      F : MC_FS.File;
      Name : Identity := Zero_Identity;
      Expected : Digest := Zero_Digest;
      Size, Written : Counter := 0;
      Hash : MC_SHA256.Context := MC_SHA256.Initialize;
      Active : Boolean := False;
   end record;
   type Store is limited record
      Directory : MC_FS.Root;
      Lock : MC_FS.File;
      Opened : Boolean := False;
   end record;
end MC_Store;
