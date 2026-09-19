package dev.weedout.ide;

import com.intellij.openapi.editor.EditorCustomElementRenderer;
import com.intellij.openapi.editor.Inlay;
import com.intellij.openapi.editor.colors.EditorColorsManager;
import com.intellij.openapi.editor.markup.TextAttributes;
import org.jetbrains.annotations.NotNull;

import java.awt.Graphics;
import java.awt.Rectangle;

final class WeedoutInlayRenderer implements EditorCustomElementRenderer {
    private final String text;
    WeedoutInlayRenderer(String text) { this.text = "  " + text; }

    @Override public int calcWidthInPixels(@NotNull Inlay inlay) {
        return inlay.getEditor().getContentComponent().getFontMetrics(inlay.getEditor().getColorsScheme().getFont(com.intellij.openapi.editor.colors.EditorFontType.PLAIN)).stringWidth(text);
    }

    @Override public void paint(@NotNull Inlay inlay, @NotNull Graphics graphics, @NotNull Rectangle targetRegion, @NotNull TextAttributes textAttributes) {
        graphics.setColor(EditorColorsManager.getInstance().getGlobalScheme().getDefaultForeground());
        var component = inlay.getEditor().getContentComponent();
        var font = inlay.getEditor().getColorsScheme().getFont(com.intellij.openapi.editor.colors.EditorFontType.PLAIN);
        var metrics = component.getFontMetrics(font);
        graphics.setFont(font);
        graphics.drawString(text, targetRegion.x, targetRegion.y + (targetRegion.height - metrics.getHeight()) / 2 + metrics.getAscent());
    }
}
