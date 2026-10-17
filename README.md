# security-skill-owasp

Skill para [Claude Code](https://claude.com/claude-code) que hace una **auditoría de seguridad estática** del código
de una aplicación contra el **OWASP Top 10:2025** y deja un informe con hallazgos, severidad, confianza, CWE y una
corrección sugerida para cada uno.

- Solo lectura sobre el código: no edita archivos, no instala dependencias ni corre scripts del proyecto.
- No ataca sistemas en vivo: describe cómo sería el ataque, no lo ejecuta.
- Cada hallazgo lleva `archivo:línea` y cómo llega a él la entrada del atacante. Lo dudoso va a "Pendientes de
  verificación".
- Enmascara los secretos que encuentra (primeros 4 caracteres + `…`).
- Si la carpeta está vacía, pide la URL de un repositorio de GitHub y lo clona (`--depth 1`) para auditarlo.
- El informe se guarda en `audit/<dd-mm-yy>/security-audit-report.md`, en el idioma del pedido, sin pisar informes
  anteriores.

## Contenido

```
security-audit/                 la skill
  SKILL.md                      instrucciones (pasos 1 a 6)
  references/
    owasp-top10-2025/           A01…A10: descripción, cómo revisarlo en código, greps, CWE
    severity.md                 criterios de severidad y confianza
  assets/report-template.md     plantilla del informe
  evals/                        casos de prueba (evals.json + fixtures con vulnerabilidades plantadas)
agents/
  security-auditor.md           subagente que corre la skill de punta a punta (opcional)
```

## Instalación

Copiá la skill (y, si querés, el subagente) en tu carpeta de Claude Code:

```bash
git clone https://github.com/nima8998/security-skill-owasp.git
cp -r security-skill-owasp/security-audit ~/.claude/skills/
cp security-skill-owasp/agents/security-auditor.md ~/.claude/agents/   # opcional
```

En Windows (PowerShell):

```powershell
git clone https://github.com/nima8998/security-skill-owasp.git
Copy-Item -Recurse security-skill-owasp\security-audit "$HOME\.claude\skills\"
Copy-Item security-skill-owasp\agents\security-auditor.md "$HOME\.claude\agents\"   # opcional
```

Para usarla en un solo proyecto, copiala en `<proyecto>/.claude/skills/` (y `<proyecto>/.claude/agents/`).

## Uso

Se activa sola con pedidos como "auditá la seguridad de esta app", "revisá este código", "¿esto es seguro?" o "buscá
mejoras en la aplicación". También se puede invocar con `/security-audit`.

## Evals

`security-audit/evals/evals.json` tiene tres casos: una API Express con vulnerabilidades plantadas, una app Flask
para un pedido de "mejoras" generales y una carpeta vacía. Los `files` de cada caso son relativos a
`security-audit/evals/`.

> Los fixtures son **código vulnerable a propósito** (inyección SQL, MD5, secreto JWT hardcodeado, `pickle`,
> `shell=True`, etc.). No los ejecutes ni los despliegues.

## Atribución

Los archivos de `references/owasp-top10-2025/` resumen y reorganizan el
[OWASP Top 10:2025](https://top10.owasp.org/2025/) — © OWASP Top 10 Team, licencia
[CC BY 3.0](https://creativecommons.org/licenses/by/3.0/). Las secciones "How to check in code" son agregados de esta
skill y no forman parte del documento de OWASP.
