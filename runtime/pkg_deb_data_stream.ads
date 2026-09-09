-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
with MC_Store; with Pkg_Deb_Container;
package Pkg_Deb_Data_Stream with SPARK_Mode => Off is
   type Observation is record
      Original, Compressed, Expanded : Digest := Zero_Digest;
      Encoded_Size, Expanded_Size : Counter := 0;
   end record;
   procedure Stage (Store : in out MC_Store.Store; Expected : Pkg_Deb_Container.Envelope;
                    Limit, Deadline : Counter; Result : out Observation; Status : out Outcome);
   -- Unprivileged original data-member -> decompressed byte object in existing CAS.
   -- Two bounded streaming passes establish then independently reproduce the hash
   -- and size required by the CAS writer. No whole input/output memory buffers.
   -- Supports raw, gzip, bzip2, LZMA-alone, xz and zstd, one complete stream only.
   -- Every encoded byte must be consumed; limits include a caller output budget.
   -- UID 0 is refused. These bytes are NOT validated tar entries, ownership,
   -- dependency/effect satisfaction, trust, authorization or a bootable generation.
   -- A failed call can leave complete unreferenced CAS blobs but publishes no state.
   -- Deadline checks surround I/O and codec steps; an outer process deadline and
   -- resource scope remain necessary for synchronous calls and whole CAS hashing.
end Pkg_Deb_Data_Stream;
