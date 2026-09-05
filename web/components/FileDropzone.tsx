"use client";

import { FolderOpen, X } from "lucide-react";
import { useRef, useState } from "react";
import type { ChangeEvent, DragEvent } from "react";

const ACCEPTED_TYPES = ["application/pdf", "image/png", "image/jpeg"];
const ACCEPTED_EXTENSIONS = ".pdf,.png,.jpg,.jpeg";
const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024; // matches backend's limit

interface FileDropzoneProps {
  file: File | null;
  onFileSelected: (file: File | null) => void;
  /** Surfaced to the parent so it can show a validation message inline
   * with the rest of the form, rather than this component owning its
   * own separate error UI. */
  onValidationError: (message: string | null) => void;
}

export function FileDropzone({
  file,
  onFileSelected,
  onValidationError,
}: FileDropzoneProps) {
  const [isDragActive, setIsDragActive] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  function validateAndSelect(candidate: File) {
    if (!ACCEPTED_TYPES.includes(candidate.type)) {
      onValidationError(
        "Unsupported file type. Please upload a PDF, PNG, or JPEG file."
      );
      return;
    }
    if (candidate.size > MAX_FILE_SIZE_BYTES) {
      onValidationError("File is too large. Maximum size is 10 MB.");
      return;
    }
    onValidationError(null);
    onFileSelected(candidate);
  }

  function handleDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setIsDragActive(false);
    const dropped = event.dataTransfer.files?.[0];
    if (dropped) validateAndSelect(dropped);
  }

  function handleInputChange(event: ChangeEvent<HTMLInputElement>) {
    const selected = event.target.files?.[0];
    if (selected) validateAndSelect(selected);
  }

  if (file) {
    return (
      <div className="flex items-center justify-between gap-3 rounded-xl border border-border bg-surface-elevated px-4 py-3">
        {/* min-w-0 is required here: a flex child with intrinsic
         * content width (an unbroken long filename) would otherwise
         * push this row wider than the viewport on mobile. */}
        <div className="flex min-w-0 flex-1 flex-col">
          <span className="truncate text-sm font-medium text-foreground">
            {file.name}
          </span>
          <span className="text-xs text-foreground-subtle">
            {(file.size / 1024).toFixed(0)} KB
          </span>
        </div>
        <button
          type="button"
          onClick={() => onFileSelected(null)}
          aria-label="Remove selected file"
          className="shrink-0 rounded-md p-1.5 text-foreground-muted hover:bg-surface hover:text-foreground"
        >
          <X className="h-4 w-4" />
        </button>
      </div>
    );
  }

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => inputRef.current?.click()}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          inputRef.current?.click();
        }
      }}
      onDragOver={(event) => {
        event.preventDefault();
        setIsDragActive(true);
      }}
      onDragLeave={() => setIsDragActive(false)}
      onDrop={handleDrop}
      className={`dropzone-border flex cursor-pointer flex-col items-center gap-3 rounded-xl px-6 py-10 text-center ${
        isDragActive ? "dropzone-active" : ""
      }`}
    >
      <span className="flex h-12 w-12 items-center justify-center rounded-full bg-surface-elevated">
        <FolderOpen className="h-6 w-6 text-accent-amber" strokeWidth={2} />
      </span>
      <p className="text-sm text-foreground">
        Drag and drop a file here, or{" "}
        <span className="font-medium text-accent-blue">browse</span>
      </p>
      <p className="text-xs text-foreground-subtle">
        Supports PDF, PNG, JPEG up to 10 MB
      </p>
      <input
        ref={inputRef}
        type="file"
        accept={ACCEPTED_EXTENSIONS}
        onChange={handleInputChange}
        className="hidden"
      />
    </div>
  );
}
