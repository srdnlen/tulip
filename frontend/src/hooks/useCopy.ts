import { useState, useCallback } from "react";

//https://stackoverflow.com/questions/51805395/navigator-clipboard-is-undefined
function copyToClipboard(textToCopy: string) {
    // navigator clipboard api needs a secure context (https)
    if (navigator.clipboard && window.isSecureContext) {
        // navigator clipboard api method'
        return navigator.clipboard.writeText(textToCopy);
    } else {
        // text area method
        let textArea = document.createElement("textarea");
        textArea.value = textToCopy;
        // make the textarea out of viewport
        textArea.style.position = "fixed";
        textArea.style.left = "-999999px";
        textArea.style.top = "-999999px";
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        return new Promise<void>((res, rej) => {
            // here the magic happens
            document.execCommand("copy") ? res() : rej();
            textArea.remove();
        });
    }
}

type CopyState = "failed" | "copied" | "copying" | "default";

const defaultCopyStateToText: Record<CopyState, string> = {
    copied: "Copied",
    default: "Copy",
    failed: "Copy failed",
    copying: "Copying",
};

interface useCopyParams {
    copyStateToText?: Record<CopyState, string>;
    getText: () => string | Promise<string>;
}

export function useCopy(params: useCopyParams) {
    const [copyState, setCopyState] = useState<CopyState>("default");

    const copyStateToText = params.copyStateToText ?? defaultCopyStateToText;

    const copyText = useCallback((textToCopy: string) => {
        return copyToClipboard(textToCopy)
            .then(() => {
                setCopyState("copied");
                setTimeout(() => setCopyState("default"), 2000);
            })
            .catch(() => setCopyState("failed"));
    }, [setCopyState]);

    const copy = useCallback(() => {
        setCopyState("copying");
        let textOrPromise: string | Promise<string>;
        try {
            textOrPromise = params.getText();
        } catch {
            setCopyState("failed");
            return;
        }

        if (typeof textOrPromise === "string") {
            copyText(textOrPromise);
            return;
        }

        textOrPromise
            .then(copyText)
            .catch(() => setCopyState("failed"));
    }, [copyText, params.getText, setCopyState]);

    return {
        copyState,
        copy,
        statusText: copyStateToText[copyState],
    };
}
