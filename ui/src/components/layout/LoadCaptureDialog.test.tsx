import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent, userEvent } from "../../test/render";
import { LoadCaptureDialog } from "./LoadCaptureDialog";
import { makeOutput } from "../../test/fixtures";

const noop = vi.fn();

describe("LoadCaptureDialog", () => {
  it("renders the dialog with the 'Load capture' heading", () => {
    render(
      <LoadCaptureDialog
        onReplaceData={noop}
        onAnalyzePcap={async () => {}}
        onClose={noop}
      />,
    );
    expect(screen.getByText("Load capture")).toBeInTheDocument();
  });

  it("renders the drag-and-drop prompt", () => {
    render(
      <LoadCaptureDialog
        onReplaceData={noop}
        onAnalyzePcap={async () => {}}
        onClose={noop}
      />,
    );
    expect(
      screen.getByText(/Drag & drop, or click to browse/i),
    ).toBeInTheDocument();
  });

  it("calls onClose when the close button is clicked", async () => {
    const u = userEvent.setup();
    const onClose = vi.fn();
    render(
      <LoadCaptureDialog
        onReplaceData={noop}
        onAnalyzePcap={async () => {}}
        onClose={onClose}
      />,
    );
    await u.click(screen.getByRole("button", { name: /Close/i }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("calls onClose when the overlay backdrop is clicked", async () => {
    const u = userEvent.setup();
    const onClose = vi.fn();
    const { container } = render(
      <LoadCaptureDialog
        onReplaceData={noop}
        onAnalyzePcap={async () => {}}
        onClose={onClose}
      />,
    );
    // The outermost fixed div is the backdrop
    const backdrop = container.firstElementChild as HTMLElement;
    await u.click(backdrop);
    expect(onClose).toHaveBeenCalled();
  });

  it("processes a summary.json file via the file input and shows ready state", async () => {
    const output = makeOutput();
    const onReplaceData = vi.fn();
    render(
      <LoadCaptureDialog
        onReplaceData={onReplaceData}
        onAnalyzePcap={async () => {}}
        onClose={noop}
      />,
    );

    // Create a fake summary.json File
    const jsonContent = JSON.stringify(output);
    const file = new File([jsonContent], "summary.json", { type: "application/json" });
    // Mock the text() method
    Object.defineProperty(file, "text", {
      value: async () => jsonContent,
      writable: false,
    });

    // Trigger the hidden file input
    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
    Object.defineProperty(fileInput, "files", {
      value: Object.assign([file], { item: (i: number) => [file][i], length: 1 }),
      writable: false,
    });
    fireEvent.change(fileInput);

    // Should eventually show the ready state (summary loaded message)
    await screen.findByText(/pkts/i, {}, { timeout: 3000 });
    expect(onReplaceData).toHaveBeenCalled();
  });

  it("shows an error when an unsupported file type is dropped via the file input", async () => {
    render(
      <LoadCaptureDialog
        onReplaceData={noop}
        onAnalyzePcap={async () => {}}
        onClose={noop}
      />,
    );

    // Use the hidden file input to trigger onChange with an unsupported file
    const file = new File(["data"], "test.txt", { type: "text/plain" });
    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
    Object.defineProperty(fileInput, "files", {
      value: Object.assign([file], { item: (i: number) => [file][i], length: 1 }),
      writable: false,
    });
    fireEvent.change(fileInput);

    // Wait for the error message to appear
    const errorMsg = await screen.findByText(
      /Drop a .pcap\/.pcapng capture/i,
    );
    expect(errorMsg).toBeInTheDocument();
  });

  it("covers onDrop and onDragOver/onDragLeave: dragging a file over the drop zone", async () => {
    render(
      <LoadCaptureDialog
        onReplaceData={noop}
        onAnalyzePcap={async () => {}}
        onClose={noop}
      />,
    );

    // Get the drop zone div
    const dropZone = screen.getAllByRole("button").find(
      (el) => el.getAttribute("tabindex") === "0" && !el.getAttribute("aria-label"),
    )!;

    // Trigger dragOver — covers the setDragging(true) callback
    fireEvent.dragOver(dropZone);
    // Trigger dragLeave — covers setDragging(false)
    fireEvent.dragLeave(dropZone);

    // Now drop an unsupported file — covers onDrop and handleFiles error path
    const file = new File(["data"], "test.txt", { type: "text/plain" });
    const fileListLike = Object.assign([file], {
      item: (i: number) => [file][i],
      length: 1,
    }) as unknown as FileList;

    fireEvent.drop(dropZone, {
      dataTransfer: { files: fileListLike },
    });

    // The error message should appear (unsupported file type)
    await screen.findByText(/Drop a .pcap\/.pcapng capture/i);
  });

  it("covers keydown handler: Enter key on drop zone triggers click", async () => {
    const u = userEvent.setup();
    render(
      <LoadCaptureDialog
        onReplaceData={noop}
        onAnalyzePcap={async () => {}}
        onClose={noop}
      />,
    );

    const dropZone = screen.getAllByRole("button").find(
      (el) => el.getAttribute("tabindex") === "0" && !el.getAttribute("aria-label"),
    )!;

    // Spy on HTMLInputElement.prototype.click to verify the hidden file input is triggered
    const clickSpy = vi.spyOn(HTMLInputElement.prototype, "click").mockImplementation(() => {});

    // Focus the drop zone and press Enter to cover the keydown handler
    await u.click(dropZone);
    fireEvent.keyDown(dropZone, { key: "Enter" });
    expect(clickSpy).toHaveBeenCalled();

    clickSpy.mockClear();
    fireEvent.keyDown(dropZone, { key: " " });
    expect(clickSpy).toHaveBeenCalled();

    clickSpy.mockRestore();
  });
});
