import { Check } from "@phosphor-icons/react/Check";
import { Palette } from "@phosphor-icons/react/Palette";
import { TextAa } from "@phosphor-icons/react/TextAa";
import { motion } from "motion/react";
import { LiquidGlass } from "../../components/ui/LiquidGlass";
import { useAppearance } from "./useAppearance";

const SCHEMES = [
  { value: "forest", label: "Standard", colors: ["#f6f7f9", "#3658ca", "#17191d"] },
  { value: "mineral", label: "Mineral", colors: ["#edf1ef", "#315f69", "#1d292b"] },
  { value: "clay", label: "Clay", colors: ["#f4eee7", "#8a553d", "#30241f"] },
  { value: "mono", label: "Ink", colors: ["#efefec", "#3d4542", "#191d1b"] },
];
const FONTS = [
  { value: "poppins", label: "Poppins", note: "Geometric" },
  { value: "system", label: "System", note: "Native" },
  { value: "editorial", label: "Editorial", note: "Serif" },
  { value: "technical", label: "Technical", note: "Mono" },
];
const SCALES = [
  { value: "compact", label: "Compact", sample: "14" },
  { value: "default", label: "Default", sample: "16" },
  { value: "large", label: "Large", sample: "18" },
];

export function AppearanceSection() {
  const { appearance, setAppearance } = useAppearance();
  return <section aria-labelledby="appearance-title" className="settings-section appearance-settings">
    <h2 id="appearance-title"><Palette aria-hidden="true" size={18} weight="duotone" /> Appearance</h2>
    <p className="settings-section__lede">Tune the workspace and admin panels for the way you read and work. Public and authentication pages keep their own fixed visual identity.</p>

    <fieldset className="appearance-fieldset"><legend>Colour scheme</legend><div className="scheme-options">
      {SCHEMES.map((option) => <label className="scheme-option" key={option.value}><input aria-label={option.label} className="visually-hidden" type="radio" name="colour-scheme" value={option.value} checked={appearance.scheme === option.value} onChange={() => setAppearance({ scheme: option.value })} />
        <span className="scheme-option__swatches" aria-hidden="true">{option.colors.map((color) => <i key={color} style={{ background: color }} />)}</span>
        <span>{option.label}</span>{appearance.scheme === option.value && <Check size={15} weight="bold" aria-hidden="true" />}
      </label>)}
    </div></fieldset>

    <fieldset className="appearance-fieldset"><legend>Typeface</legend><div className="font-options">
      {FONTS.map((option) => <label className={`font-option font-option--${option.value}`} key={option.value}><input aria-label={`${option.label} — ${option.note}`} className="visually-hidden" type="radio" name="typeface" value={option.value} checked={appearance.font === option.value} onChange={() => setAppearance({ font: option.value })} />
        <TextAa aria-hidden="true" size={18} /><strong>{option.label}</strong><small>{option.note}</small>
      </label>)}
    </div></fieldset>

    <fieldset className="appearance-fieldset"><legend>Text size</legend><div className="scale-options">
      {SCALES.map((option) => <label key={option.value}><input aria-label={`${option.label} — ${option.sample}px`} className="visually-hidden" type="radio" name="text-size" value={option.value} checked={appearance.scale === option.value} onChange={() => setAppearance({ scale: option.value })} /><span>{option.sample}</span>{option.label}</label>)}
    </div></fieldset>

    <div className="appearance-glass-row"><div><strong>Liquid surfaces</strong><p>Use responsive translucent surfaces and light that follows the pointer.</p></div><label className="switch"><input aria-label="Liquid surfaces" checked={appearance.glass} onChange={(event) => setAppearance({ glass: event.target.checked })} type="checkbox" /><span aria-hidden="true" /></label></div>

    <LiquidGlass className="appearance-preview" interactive>
      <span className="eyebrow">Live preview / {appearance.scheme}</span>
      <motion.div layout className="appearance-preview__finding"><span>HIGH</span><div><strong>lodash@4.17.19</strong><small>Dependency path and fix attached</small></div><Check size={18} weight="bold" aria-hidden="true" /></motion.div>
    </LiquidGlass>
  </section>;
}
