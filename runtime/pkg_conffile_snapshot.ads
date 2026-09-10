-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Finalization; with System;
with MC_Types; use MC_Types;
with MC_Store; with Pkg_Conffile_Transition;
package Pkg_Conffile_Snapshot with SPARK_Mode => Off is
   type Snapshot is new Ada.Finalization.Limited_Controlled with private;
   procedure Capture (Store : in out MC_Store.Store; Root_FD : Integer;
      Path : String; Limit, Deadline : Counter; Value : in out Snapshot; Status : out Outcome);
   procedure Recheck (Store : MC_Store.Store; Value : in out Snapshot;
      Deadline : Counter; Status : out Outcome);
   function Current (Value : Snapshot) return Pkg_Conffile_Transition.Image;
   function Metadata (Value : Snapshot) return Digest;
   procedure Clear (Value : in out Snapshot);
   -- Root_FD is a borrowed directory descriptor selected by the controller, not
   -- a path or an authority claim. The snapshot duplicates it; caller keeps the
   -- SAME open Store alive throughout capture/recheck. Raw absolute Path is
   -- relative to that root. Protected directories, same mount, no symlink
   -- traversal; genuine missing ancestors are retained with their location.
   -- Regular bytes and versioned observation metadata (including visible
   -- xattrs/ACLs, flags, signed timestamps and namespace identities) are kept in
   -- the existing CAS. No pins or installed database are created. Unsupported
   -- links/types, inaccessible attributes or O_NOATIME permission fail closed.
   -- A failure clears Value; unreferenced CAS objects can remain. Current on a
   -- cleared snapshot is Other, NEVER Missing. Reads require a trusted procfs.
   -- Effective UID/GID are recorded. Credential-hidden xattrs are not attested;
   -- a privileged attribute observer is still required for full root assembly.
   -- Recheck reopens from the held root and rehashes content/metadata. This is
   -- optimistic observation, not a filesystem freeze or protection against all
   -- privileged concurrent changes. Controller must bind root identity, user
   -- choice, retention and final recheck to the full managed publication.
private
   type Snapshot is new Ada.Finalization.Limited_Controlled with record
      Handle : System.Address := System.Null_Address;
      Reservation : Integer := -1;
      Image : Pkg_Conffile_Transition.Image := (Pkg_Conffile_Transition.Other, Zero_Digest);
      Meta : Digest := Zero_Digest;
   end record;
   overriding procedure Finalize (Value : in out Snapshot);
end Pkg_Conffile_Snapshot;
