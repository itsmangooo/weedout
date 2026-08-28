import {
  ArrowRight,
  Check,
  Code2,
  FileKey2,
  GitBranch,
  PackageSearch,
  ShieldCheck,
  TerminalSquare,
} from "lucide-react";
import { Link } from "react-router";

import { WeedoutLogo } from "../components/brand/WeedoutLogo";
import ownerPhoto from "../assets/emanuel-rm-linkedin.jpg";
import { ProductScreenshot } from "../features/landing/components/ProductScreenshot";
import { SystemStatus } from "../features/system/components/SystemStatus";

const MODULES = [
  {
    Icon: PackageSearch,
    title: "Dependency intelligence",
    description:
      "Scan supported manifests, connect exploit and reachability signals, and filter findings that do not deserve attention.",
    status: "Available now",
    available: true,
  },
  {
    Icon: Code2,
    title: "Source-code analysis",
    description:
      "A future analysis surface for code-level findings, designed to live beside dependency risk instead of in another tool.",
    status: "Planned",
  },
  {
    Icon: FileKey2,
    title: "Secrets detection",
    description:
      "A reserved project module for exposed credentials and sensitive values, with no scanner implied before it exists.",
    status: "Planned",
  },
  {
    Icon: GitBranch,
    title: "CI & configuration",
    description:
      "A future home for workflow, infrastructure and security configuration findings at project level.",
    status: "Planned",
  },
];

const CURRENT_CAPABILITIES = [
  "Supported manifest scanning",
  "OSV advisory matching",
  "Known-exploited prioritisation",
  "Reachability and depth context",
  "Alert rules and noise filtering",
  "Web, CLI and CI workflows",
];

export function FoundationPage() {
  return (
    <div className="landing-page">
      <section className="landing-section landing-hero" aria-labelledby="landing-title">
        <div className="landing-hero__copy">
          <span className="landing-pill">
            <ShieldCheck aria-hidden="true" size={15} /> Dependency security, without the noise
          </span>
          <h1 id="landing-title">See the security issues that actually deserve attention.</h1>
          <p className="landing-hero__lede">
            Weedout turns vulnerable dependency data into a clear project-level decision queue.
            Start with dependency risk today, inside a workspace designed to grow without becoming
            another wall of red.
          </p>
          <div className="landing-actions">
            <Link className="button button--primary landing-action" to="/signup">
              Start scanning free <ArrowRight aria-hidden="true" size={16} />
            </Link>
            <a className="button button--ghost landing-action" href="#product">
              See the product
            </a>
          </div>
          <div className="landing-hero__proof" aria-label="Current product capabilities">
            <span><Check aria-hidden="true" size={14} /> Open source</span>
            <span><Check aria-hidden="true" size={14} /> CLI + web</span>
            <span><Check aria-hidden="true" size={14} /> No card required</span>
          </div>
        </div>

        <div className="landing-hero__product">
          <ProductScreenshot />
        </div>
      </section>

      <section className="landing-trust" aria-label="Weedout product principles">
        <p>Built for small teams that need security clarity, not security theatre.</p>
        <div>
          <span>AGPL-3.0</span>
          <span>OSV advisories</span>
          <span>CISA KEV context</span>
          <a
            href="https://votekicker.com/weedout?utm_source=votekicker&utm_medium=badge&utm_campaign=weedout"
            rel="noopener noreferrer"
            target="_blank"
          >
            Featured on Votekicker
          </a>
        </div>
      </section>

      <section className="landing-section landing-product" id="product" aria-labelledby="product-title">
        <div className="landing-section__intro">
          <p className="section-label">The product today</p>
          <h2 id="product-title">A calm workspace for dependency risk.</h2>
          <p>
            Weedout does not celebrate finding the largest number of CVEs. It combines severity,
            exploitation and project context so the queue stays useful when it matters.
          </p>
        </div>

        <div className="landing-product__grid">
          <div className="landing-product__copy">
            <ol className="landing-steps">
              <li>
                <span>01</span>
                <div>
                  <strong>Add a real project</strong>
                  <p>Upload a supported manifest or connect the existing CLI and CI flow.</p>
                </div>
              </li>
              <li>
                <span>02</span>
                <div>
                  <strong>Let context remove noise</strong>
                  <p>Alert rules, dependency depth and exploit signals separate mmtÓN-¢G§²ÚîÆ­yÚ\Èİ[Û™H\]Ø^Kˆ
‹ÂYYXH
X^]ÚYˆ™[JHÂˆ˜\\Ú[Âˆ\Ü^Nˆ›ØÚÎÂˆB‚ˆ˜\\ÚYX˜\ˆÂˆÜÚ][ÛˆİXÚŞNÂˆÜˆÂˆ‹Z[™^ˆÌÂˆ\Ü^Nˆ›ØÚÎÂˆÚYˆL	NÂˆZYÚˆ]]ÎÂˆY[™ÎˆÜ™[H\™[NÂˆ›Ü™\‹\šYÚˆÂˆ›Ü™\‹X›İÛNˆ\ÛÛY˜\ŠK]ÛËX›Ü™\ŠNÂˆ˜XÚÙÜ›İ[™ˆ˜\ŠK]ÛË]™Z[
NÂˆ˜XÚÙ›ÜYš[\ˆ›\ŠMœ
NÂˆB‚ˆ˜\\Ú[×ÛY[HÂˆ\Ü^Nˆ[›[™KY›^ÂˆB‚ˆ˜\\ÚYX˜\—×Ü[™[Âˆ\Ü^Nˆ›Û™NÂˆB‚ˆš\Ë[˜]‹[Ü[ˆ˜\\ÚYX˜\—×Ü[™[Âˆ\Ü^NˆÜšYÂˆØ\ˆ˜\ŠK]ÛË\ÜXÙKM
NÂˆY[™Ë]Üˆ˜\ŠK]ÛË\ÜXÙKM
NÂˆX\™Ú[‹]Üˆ˜\ŠK]ÛË\ÜXÙKLÊNÂˆ›Ü™\‹]Üˆ\ÛÛY˜\ŠK]ÛËX›Ü™\ŠNÂˆB‚ˆ˜\\Ú[×Û˜]ˆÂˆX\™Ú[‹]ÜˆÂˆB‚ˆ˜\\Ú[×Ù›ÛİÂˆX\™Ú[‹]ÜˆÂˆB‚ˆ˜\\Ú[×ÛXZ[ˆÂˆÚYˆZ[ŠL	HHœ™[K˜\ŠK]ÛËX\[X^
JNÂˆBŸB‚YYXH
X^]ÚYˆ™[JHÂˆ™\Ú›Ø\™ZXY\‹ˆ˜][[Û‹\İ[[X\W×Ø›ÙHÂˆ[YÛ‹Z][\Îˆ›^\İ\ÂˆB‚ˆ™\Ú›Ø\™ZXY\ˆÂˆ›^Y\™Xİ[ÛˆÛÛ[[ÂˆB‚ˆ˜][[Û‹\İ[[X\W×Ø›ÙHÂˆÜšY][\]KXÛÛ[[œÎˆYœÂˆB‚ˆ˜][[Û‹\İ[[X\W×ÛY\ÜØYÙHÂˆÜšY][\]KXÛÛ[[œÎˆ]]ÈZ[›X^
YœŠNÂˆB‚ˆ˜][[Û‹\İ[[X\W×ØÜš]XØ[ÂˆÜšYXÛÛ[[ˆÂˆB‚ˆ˜][[Û‹\İ[[X\H˜]ÛˆÂˆÚYˆL	NÂˆB‚ˆœ›Ú™Xİ\›İ××ÛXZ[ˆÂˆÜšY][\]KXÛÛ[[œÎˆZ[›X^
YœŠH]]ÎÂˆB‚ˆœ›Ú™Xİ\›İ××Ùš[™[™ÜÈÂˆÜšYXÛÛ[[ˆHÈLNÂˆB‚ˆœ›Ú™Xİ\›İ××Ø\œ›İÈÂˆÜšYXÛÛ[[ˆÂˆÜšY\›İÎˆNÂˆBŸB‚YYXH
X^]ÚYˆ™[JHÂˆ˜\\Ú[×Û˜]‹[[šÈÂˆY[™ËZ[›[™NˆM\™[NÂˆB‚ˆÊˆİXÚÙYˆHY[HšYÙÙ\ˆÛÙ\È˜XÚÈÛˆH]H[™H˜]\ˆ[‚ˆ›Ø][™È]HÜšYÚÙˆHØ\™]›ÈÛ™Ù\ˆÚ]È™\ÚYKˆ
‹Âˆ™š[™[™Ë\›İÈÂˆÜšY][\]KXÛÛ[[œÎˆZ[›X^
YœŠH]]ÎÂˆ[YÛ‹Z][\Îˆİ\ÂˆØ\ˆ˜\ŠK]ÛË\ÜXÙKLŠNÂˆY[™Îˆ˜\ŠK]ÛË\ÜXÙKM
NÂˆB‚ˆ™š[™[™Ë\›İ××ÚY[]HÂˆÜšYXÛÛ[[ˆNÂˆÜšY\›İÎˆNÂˆB‚ˆ™š[™[™Ë\›İÈˆ™[]K[Y[K]šYÙÙ\ˆÂˆÜšYXÛÛ[[ˆÂˆÜšY\›İÎˆNÂˆB‚ˆ™š[™[™Ë\›İ××Ü›Ú™Xİˆ™š[™[™Ë\›İ××ÜÚYÛ˜[Ëˆ™š[™[™Ë\›İ××Üİ]HÂˆÜšYXÛÛ[[ˆHÈLNÂˆÜšY\›İÎˆ]]ÎÂˆB‚ˆ™š[™[™Ë\›İ××Üİ]HÂˆ\Ü^Nˆ›^Âˆ[YÛ‹Z][\Îˆ˜\Ù[[™NÂˆØ\ˆ˜\ŠK]ÛË\ÜXÙKLŠNÂˆB‚ˆ™\Ú›Ø\™\YÙHÂˆY[™Ë]Üˆ˜\ŠK]ÛË\ÜXÙKMÊNÂˆB‚ˆ™\Ú›Ø\™ZXY\—×ØXİ[ÛœËˆ™\Ú›Ø\™ZXY\—×ØXİ[ÛœÈ˜]ÛˆÂˆÚYˆL	NÂˆB‚ˆ›Ü[‹Yš[™[™Ü××ÚXY[™ÈÂˆ[YÛ‹Z][\Îˆ›^\İ\ÂˆB‚ˆ™š[™[™Ë\›İÈÂˆÜšY][\]KXÛÛ[[œÎˆZ[›X^
YœŠH]]ÎÂˆØ\ˆ˜\ŠK]ÛË\ÜXÙKLÊNÂˆY[™ËX›ØÚÎˆ˜\ŠK]ÛË\ÜXÙKMJNÂˆB‚ˆ™š[™[™Ë\›İ××ÚY[]Kˆ™š[™[™Ë\›İ××Ü›Ú™Xİˆ™š[™[™Ë\›İ××ÜÚYÛ˜[Ëˆ™š[™[™Ë\›İ××Üİ]HÂˆÜšYXÛÛ[[ˆNÂˆÜšY\›İÎˆ]]ÎÂˆB‚ˆ™š[™[™Ë\›İ××Üİ]HÂˆ\Ü^Nˆ›^Âˆ\İYKXÛÛ[ˆ›^\İ\ÂˆØ\ˆ˜\ŠK]ÛË\ÜXÙKLÊNÂˆB‚ˆ™š[™[™Ë\›İÈˆ™[]K[Y[K]šYÙÙ\ˆÂˆÜšYXÛÛ[[ˆÂˆÜšY\›İÎˆNÂˆB‚ˆœ›Ú™Xİ[\İ×ÚXY[™Ëˆ™š[™[™Ë\İ[[X\Kˆ›Ü[‹Yš[™[™Ü××ÚXY[™ÈÂˆY[™Îˆ˜\ŠK]ÛË\ÜXÙKMJNÂˆB‚ˆœ›Ú™Xİ\›İ××ÛXZ[ˆÂˆÜšY][\]KXÛÛ[[œÎˆYœÂˆØ\ˆ˜\ŠK]ÛË\ÜXÙKM
NÂˆB‚ˆœ›Ú™Xİ\›İ××Ø\œ›İÈÂˆ\Ü^Nˆ›Û™NÂˆB‚ˆ™š[™[™Ë\İ[[X\W×ØÛİ[ÈÂˆÜšY][\]KXÛÛ[[œÎˆ™\X]
‹Z[›X^
YœŠJNÂˆB‚ˆ™\Ú›Ø\™Y[\HÂˆÜšY][\]KXÛÛ[[œÎˆYœÂˆB‚ˆ™\Ú›Ø\™Y[\H˜]ÛˆÂˆÚYˆL	NÂˆBŸB‚YYXH
™Y™\œË\™YXÙY[[İ[Ûˆ™YXÙJHÂˆ™\Ú›Ø\™\]Y\K\İ]W×ÜÜ[›™\ˆÂˆ[š[X][Ûˆ›Û™NÂˆBŸB‚‹ÊˆKKHÛÙØXTÈÛÜšÜÜXÙHKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKBˆH\XØ][Ûˆœ˜[YH\È[X™\˜][H]ZY]\ˆ[ˆH]H]ÛÛZ[œË‚ˆ™Y[X™\ˆ[™Ü™Y[ˆİ^H™\Ù\™Y›Üˆš[™[™ÜÈ[™ØØ[ˆİ]NÈ˜]šYØ][Û‹ˆ[Ù[\È[™Ü™[˜\HØ\™È\ÙH™]]˜[İ\™˜XÙ\È[™Hœ˜[™XØÙ[ˆ
‹Â‚‹˜\\Ú[ÂˆÜšY][\]KXÛÛ[[œÎˆMÜ™[HZ[›X^
YœŠNÂˆØ\ˆ˜\ŠK]ÛË\ÜXÙKLÊNÂˆY[™Ë\šYÚˆ˜\ŠK]ÛË\ÜXÙKLÊNÂŸB‚‹˜\\ÚYX˜\ˆÂˆÜˆ˜\ŠK]ÛË\ÜXÙKLÊNÂˆZYÚˆØ[ÊLšH
˜\ŠK]ÛË\ÜXÙKLÊH
ˆŠJNÂˆX\™Ú[ˆ˜\ŠK]ÛË\ÜXÙKLÊH˜\ŠK]ÛË\ÜXÙKLÊH˜\ŠK]ÛË\ÜXÙKLÊNÂˆY[™Îˆ˜\ŠK]ÛË\ÜXÙKM
NÂˆİ™\™›İÎˆY[Âˆ›Ü™\ˆ\ÛÛY˜\ŠK]ÛËX›Ü™\ŠNÂˆ›Ü™\‹\˜Y]\Îˆ˜\ŠK]ÛË\˜Y]\Ë^
NÂˆ˜XÚÙÜ›İ[™ˆ˜\ŠK]ÛË\İ\™˜XÙJNÂˆ›Ş\ÚYİÎˆ˜\ŠK]ÛË\ÚYİË\ÛÙ
NÂŸB‚‹˜\\ÚYX˜\—×Ü[™[Âˆİ™\™›İË^Nˆ]]ÎÂˆØÜ›Û˜\‹]ÚYˆ[ÂŸB‚‹˜\\Ú[×Øœ˜[™ÂˆY[™ËZ[›[™Nˆ\™[NÂŸB‚‹˜\\Ú[×Û˜]ˆÂˆØ\ˆ˜\ŠK]ÛË\ÜXÙKMJNÂˆX\™Ú[‹]Üˆ˜\ŠK]ÛË\ÜXÙKMŠNÂŸB‚‹˜\\Ú[×Û˜]‹YÜ›İ\Âˆ\Ü^NˆÜšYÂˆØ\ˆŒœ™[NÂŸB‚‹˜\\Ú[×Û˜]‹[X™[ÂˆX\™Ú[ˆ˜\ŠK]ÛË\ÜXÙKLŠNÂˆY[™ËZ[›[™Nˆ\™[NÂˆÛÛÜˆ˜\ŠK]ÛË]^Y[JNÂˆ›Û\Ú^™Nˆœ™[NÂˆ›Û]ÙZYÚˆLÂˆ]\‹\ÜXÚ[™ÎˆŒ[NÂˆ^]˜[œÙ›Ü›Nˆ\\˜Ø\ÙNÂŸB‚‹˜\\Ú[×Û˜]‹[[šÈÂˆZ[‹ZZYÚˆ‹œ™[NÂˆ›Ü™\‹\˜Y]\Îˆ˜\ŠK]ÛË\˜Y]\Ë\ÛJNÂˆÛÛÜˆ˜\ŠK]ÛË]^[]]Y
NÂˆ›Û\Ú^™NˆÎ™[NÂŸB‚‹˜\\Ú[×Û˜]‹[[šÈˆÜ[ˆÂˆZ[‹]ÚYˆÂˆ›^ˆNÂŸB‚‹˜\\Ú[×Û˜]‹[[šÎšİ™\ˆÂˆ˜XÚÙÜ›İ[™ˆ˜\ŠK]ÛË\İ\™˜XÙK[İÊNÂˆÛÛÜˆ˜\ŠK]ÛË]^
NÂŸB‚‹˜\\Ú[×Û˜]‹[[šËš\ËXXİ]™HÂˆ˜XÚÙÜ›İ[™ˆ˜\ŠK]ÛËXXØÙ[\]ZY]
NÂˆÛÛÜˆ˜\ŠK]ÛËXXØÙ[\İ›Û™ÊNÂŸB‚‹˜\\Ú[×Û˜]‹[[šËK[[Ù[HÂˆİ\œÛÜˆY˜][ÂŸB‚‹˜\\Ú[×Û˜]‹[[šËK[[Ù[Nšİ™\ˆÂˆ˜XÚÙÜ›İ[™ˆ˜[œÜ\™[ÂˆÛÛÜˆ˜\ŠK]ÛË]^[]]Y
NÂŸB‚‹˜\\Ú[×Û˜]‹[[šËK[[Ù[VØ\šXKY\ØX›YHYH—HÂˆÛÛÜˆ˜\ŠK]ÛË]^Y[JNÂŸB‚‹˜\\Ú[×Û˜]‹[[šËK[[Ù[HÛX[ÂˆY[™ÎˆŒ\™[HŒÎ™[NÂˆ›Ü™\‹\˜Y]\ÎˆNN\Âˆ˜XÚÙÜ›İ[™ˆ˜\ŠK]ÛË\İ\™˜XÙK[İÊNÂˆÛÛÜˆ˜\ŠK]ÛË]^Y[JNÂˆ›Û\Ú^™Nˆ\™[NÂˆ›Û]ÙZYÚˆÂŸB‚‹˜\\Ú[×Û˜]‹[[šËK[[Ù[Kš\ËXİ\œ™[ÂˆÛÛÜˆ˜\ŠK]ÛË]^[]]Y
NÂŸB‚‹˜\\Ú[×Û˜]‹[[šËK[[Ù[Kš\ËXİ\œ™[ÛX[Âˆ˜XÚÙÜ›İ[™ˆ˜\ŠK]ÛË\İXØÙ\ÜË\]ZY]
NÂˆÛÛÜˆ˜\ŠK]ÛË\İXØÙ\ÜÊNÂŸB‚‹˜\\Ú[×Ù›ÛİÂˆX\™Ú[‹]Üˆ˜\ŠK]ÛË\ÜXÙKMJNÂˆY[™Ë]Üˆ˜\ŠK]ÛË\ÜXÙKM
NÂŸB‚‹˜\\Ú[×ÛXZ[ˆÂˆÚYˆZ[ŠL	HHÛ[\
œ™[K]Ë\™[JK˜\ŠK]ÛËX\[X^
JNÂŸB‚‹™\Ú›Ø\™\YÙHÂˆY[™ËX›ØÚÎˆÛ[\
œ™[KËËÍ\™[JH\™[NÂŸB‚‹™\Ú›Ø\™ZXY\ˆÂˆ[YÛ‹Z][\ÎˆÙ[\ÂŸB‚‹™\Ú›Ø\™ZXY\ˆK‹™\Ú›Ø\™\]Y\K\İ]HHÂˆX^]ÚYˆ›Û™NÂˆ›Û\Ú^™NˆÛ[\
‹Œ\™[KËËÍ\™[JNÂˆ›Û]ÙZYÚˆŒÂˆ]\‹\ÜXÚ[™ÎˆLŒMY[NÂˆ[™KZZYÚˆNÂŸB‚‹™\Ú›Ø\™ZXY\—×ÛYHÂˆX^]ÚYˆ™[NÂˆX\™Ú[‹]Üˆ˜\ŠK]ÛË\ÜXÙKLÊNÂˆÛÛÜˆ˜\ŠK]ÛË]^[]]Y
NÂˆ›Û\Ú^™Nˆ™[NÂˆ[™KZZYÚˆKNÂŸB‚‹™\Ú›Ø\™ZXY\—×ØÛÛ^ÂˆX\™Ú[‹]Üˆ˜\ŠK]ÛË\ÜXÙKM
NÂŸB‚‹œÙXİ\š]KXÛİ™\˜YÙHÂˆX\™Ú[‹]Üˆ˜\ŠK]ÛË\ÜXÙKMÊNÂŸB‚‹œÙXİ\š]KXÛİ™\˜YÙW×ÚXY[™ÈÂˆ\Ü^Nˆ›^Âˆ[YÛ‹Z][\Îˆ›^Y[™Âˆ\İYKXÛÛ[ˆÜXÙKX™]ÙY[ÂˆØ\ˆ˜\ŠK]ÛË\ÜXÙKMŠNÂˆX\™Ú[‹X›İÛNˆ˜\ŠK]ÛË\ÜXÙKM
NÂŸB‚‹œÙXİ\š]KXÛİ™\˜YÙW×ÚXY[™ÈˆÂˆX\™Ú[‹]Üˆ˜\ŠK]ÛË\ÜXÙKLŠNÂˆ›Û\Ú^™NˆÛ[\
KŒ\™[KËKÜ™[JNÂˆ›Û]ÙZYÚˆŒÌÂˆ]\‹\ÜXÚ[™ÎˆLŒÍY[NÂŸB‚‹œÙXİ\š]KXÛİ™\˜YÙW×ÚXY[™ÈˆÂˆX^]ÚYˆÍ\™[NÂˆÛÛÜˆ˜\ŠK]ÛË]^Y[JNÂˆ›Û\Ú^™NˆÍœ™[NÂˆ[™KZZYÚˆKMNÂˆ^X[YÛˆšYÚÂŸB‚‹œÙXİ\š]KXÛİ™\˜YÙW×ÙÜšYÂˆ\Ü^NˆÜšYÂˆÜšY][\]KXÛÛ[[œÎˆ™\X]
Z[›X^
YœŠJNÂˆØ\ˆ˜\ŠK]ÛË\ÜXÙKLÊNÂŸB‚‹œÙXİ\š]K[[Ù[HÂˆ\Ü^Nˆ›^ÂˆZ[‹ZZYÚˆLK\™[NÂˆ›^Y\™Xİ[ÛˆÛÛ[[ÂˆY[™Îˆ˜\ŠK]ÛË\ÜXÙKM
NÂˆ›Ü™\ˆ\ÛÛY˜\ŠK]ÛËX›Ü™\ŠNÂˆ›Ü™\‹\˜Y]\Îˆ˜\ŠK]ÛË\˜Y]\Ë[ÊNÂˆ˜XÚÙÜ›İ[™ˆÛÛÜ‹[Z^
[ˆÜ™Ø‹˜\ŠK]ÛË\İ\™˜XÙK[İÊHŒ	K˜\ŠK]ÛË\İ\™˜XÙJJNÂˆÛÛÜˆ[š\š]Âˆ^YXÛÜ˜][Ûˆ›Û™NÂŸB‚‹œÙXİ\š]K[[Ù[KKXXİ]™HÂˆ›Ü™\‹XÛÛÜˆÛÛÜ‹[Z^
[ˆÜ™Ø‹˜\ŠK]ÛËXXØÙ[
HŒ‰K˜\ŠK]ÛËX›Ü™\ŠJNÂˆ˜XÚÙÜ›İ[™ˆ˜\ŠK]ÛË\İ\™˜XÙKZYÚ
NÂˆ›Ş\ÚYİÎˆ˜\ŠK]ÛË\ÚYİË\ÛÙ
NÂˆ˜[œÚ][Û‚ˆ›Ü™\‹XÛÛÜˆ˜\ŠK]ÛËY\˜][Û‹Y˜\İ
Kˆ˜[œÙ›Ü›H˜\ŠK]ÛËY\˜][ÛŠH˜\ŠK]ÛËYX\ÙK[İ]
NÂŸB‚‹œÙXİ\š]K[[Ù[KKXXİ]™Nšİ™\ˆÂˆ›Ü™\‹XÛÛÜˆÛÛÜ‹[Z^
[ˆÜ™Ø‹˜\ŠK]ÛËXXØÙ[
H‰K˜\ŠK]ÛËX›Ü™\ŠJNÂˆ˜[œÙ›Ü›Nˆ˜[œÛ]VJLœ
NÂŸB‚‹œÙXİ\š]K[[Ù[KK\[›™YÂˆÛÛÜˆ˜\ŠK]ÛË]^[]]Y
NÂŸB‚‹œÙXİ\š]K[[Ù[W×İÜÂˆ\Ü^Nˆ›^Âˆ[YÛ‹Z][\ÎˆÙ[\Âˆ\İYKXÛÛ[ˆÜXÙKX™]ÙY[ÂˆØ\ˆ˜\ŠK]ÛË\ÜXÙKLÊNÂŸB‚‹œÙXİ\š]K[[Ù[W×ÚXÛÛˆÂˆ\Ü^NˆÜšYÂˆÚYˆ‹ŒÍ\™[NÂˆZYÚˆ‹ŒÍ\™[NÂˆXÙKZ][\ÎˆÙ[\Âˆ›Ü™\‹\˜Y]\ÎˆÎ™[NÂˆ˜XÚÙÜ›İ[™ˆ˜\ŠK]ÛËXXØÙ[\]ZY]
NÂˆÛÛÜˆ˜\ŠK]ÛËXXØÙ[\İ›Û™ÊNÂŸB‚‹œÙXİ\š]K[[Ù[W×Üİ]\ÈÂˆY[™ÎˆŒ™[Hœ™[NÂˆ›Ü™\‹\˜Y]\ÎˆNN\Âˆ˜XÚÙÜ›İ[™ˆ˜\ŠK]ÛË\İ\™˜XÙK[İÊNÂˆÛÛÜˆ˜\ŠK]ÛË]^Y[JNÂˆ›Û\Ú^™NˆM™[NÂˆ›Û]ÙZYÚˆÂŸB‚‹œÙXİ\š]K[[Ù[W×Üİ]\Ëš\ËXXİ]™HÂˆ˜XÚÙÜ›İ[™ˆ˜\ŠK]ÛË\İXØÙ\ÜË\]ZY]
NÂˆÛÛÜˆ˜\ŠK]ÛË\İXØÙ\ÜÊNÂŸB‚‹œÙXİ\š]K[[Ù[Hˆİ›Û™ÈÂˆX\™Ú[‹]Üˆ]]ÎÂˆY[™Ë]Üˆ˜\ŠK]ÛË\ÜXÙKMJNÂˆ›Û\Ú^™Nˆ™[NÂŸB‚‹œÙXİ\š]K[[Ù[HˆÂˆX\™Ú[‹]Üˆ˜\ŠK]ÛË\ÜXÙKLŠNÂˆÛÛÜˆ˜\ŠK]ÛË]^Y[JNÂˆ›Û\Ú^™NˆÜ™[NÂˆ[™KZZYÚˆKNÂŸB‚‹œÙXİ\š]K[[Ù[W×ÛY]šXÈÂˆ\Ü^Nˆ›^Âˆ[YÛ‹Z][\ÎˆÙ[\Âˆ\İYKXÛÛ[ˆÜXÙKX™]ÙY[ÂˆX\™Ú[‹]Üˆ˜\ŠK]ÛË\ÜXÙKLÊNÂˆÛÛÜˆ˜\ŠK]ÛË]^[]]Y
NÂˆ›Û\Ú^™Nˆ™[NÂˆ›Û]ÙZYÚˆLÂŸB‚‹˜][[Û‹\İ[[X\HÂˆX\™Ú[‹]Üˆ˜\ŠK]ÛË\ÜXÙKMJNÂˆ›Ü™\ˆ\ÛÛY˜\ŠK]ÛËX›Ü™\ŠNÂˆ›Ü™\‹\˜Y]\Îˆ˜\ŠK]ÛË\˜Y]\Ë^
NÂˆ›Ş\ÚYİÎˆ›Û™NÂŸB‚‹˜][[Û‹\İ[[X\KKY^Ú]YÂˆ›Ü™\‹XÛÛÜˆÛÛÜ‹[Z^
[ˆÜ™Ø‹˜\ŠK]ÛËXÜš]XØ[
H	K˜\ŠK]ÛËX›Ü™\ŠJNÂˆ›Ş\ÚYİÎˆ›Û™NÂŸB‚‹˜][[Û‹\İ[[X\KK[Ü[ˆÂˆ›Ü™\‹XÛÛÜˆÛÛÜ‹[Z^
[ˆÜ™Ø‹˜\ŠK]ÛË]Ø\›š[™ÊH	K˜\ŠK]ÛËX›Ü™\ŠJNÂˆ›Ş\ÚYİÎˆ›Û™NÂŸB‚‹˜][[Û‹\İ[[X\KKXÛX\ˆÂˆ›Ü™\‹XÛÛÜˆÛÛÜ‹[Z^
[ˆÜ™Ø‹˜\ŠK]ÛË\İXØÙ\ÜÊH	K˜\ŠK]ÛËX›Ü™\ŠJNÂˆ›Ş\ÚYİÎˆ›Û™NÂŸB‚‹›Ü[‹Yš[™[™ÜË‹œ›Ú™Xİ[\İ‹™š[™[™Ë\İ[[X\K‹™\Ú›Ø\™Y[\HÂˆ›Ü™\ˆ\ÛÛY˜\ŠK]ÛËX›Ü™\ŠNÂˆ›Ü™\‹\˜Y]\Îˆ˜\ŠK]ÛË\˜Y]\Ë^
NÂˆ˜XÚÙÜ›İ[™ˆ˜\ŠK]ÛË\İ\™˜XÙKZYÚ
NÂˆ›Ş\ÚYİÎˆ˜\ŠK]ÛË\ÚYİË\ÛÙ
NÂŸB‚‹œ›Ú™Xİ\›İ××ÛXZ[ˆÂˆ›Ü™\‹\˜Y]\Îˆ˜\ŠK]ÛË\˜Y]\Ë\ÛJNÂŸB‚YYXH
X^]ÚYˆÎ™[JHÂˆœÙXİ\š]KXÛİ™\˜YÙW×ÙÜšYÂˆÜšY][\]KXÛÛ[[œÎˆ™\X]
‹Z[›X^
YœŠJNÂˆBŸB‚YYXH
X^]ÚYˆ™[JHÂˆ˜\\Ú[ÂˆY[™Ë\šYÚˆÂˆB‚ˆ˜\\ÚYX˜\ˆÂˆÜˆÂˆZYÚˆ]]ÎÂˆX\™Ú[ˆÂˆY[™ÎˆÜ™[H\™[NÂˆİ™\™›İÎˆš\ÚX›NÂˆ›Ü™\‹]ÚYˆ\Âˆ›Ü™\‹\˜Y]\ÎˆÂˆ˜XÚÙÜ›İ[™ˆ˜\ŠK]ÛË]™Z[
NÂˆ›Ş\ÚYİÎˆ›Û™NÂˆB‚ˆ˜\\ÚYX˜\—×Ü[™[Âˆİ™\™›İË^Nˆš\ÚX›NÂˆB‚ˆš\Ë[˜]‹[Ü[ˆ˜\\ÚYX˜\—×Ü[™[ÂˆX^ZZYÚˆØ[ÊLšH\™[JNÂˆİ™\™›İË^Nˆ]]ÎÂˆB‚ˆ˜\\Ú[×Û˜]ˆÂˆØ\ˆ˜\ŠK]ÛË\ÜXÙKM
NÂˆB‚ˆ˜\\Ú[×ÛXZ[ˆÂˆÚYˆZ[ŠL	HHœ™[K˜\ŠK]ÛËX\[X^
JNÂˆBŸB‚YYXH
X^]ÚYˆ™[JHÂˆœÙXİ\š]KXÛİ™\˜YÙW×ÚXY[™ÈÂˆ[YÛ‹Z][\Îˆ›^\İ\Âˆ›^Y\™Xİ[ÛˆÛÛ[[ÂˆB‚ˆœÙXİ\š]KXÛİ™\˜YÙW×ÚXY[™ÈˆÂˆ^X[YÛˆYÂˆBŸB‚YYXH
X^]ÚYˆÎ™[JHÂˆœÙXİ\š]KXÛİ™\˜YÙW×ÙÜšYÂˆÜšY][\]KXÛÛ[[œÎˆYœÂˆB‚ˆœÙXİ\š]K[[Ù[HÂˆZ[‹ZZYÚˆL™[NÂˆBŸB