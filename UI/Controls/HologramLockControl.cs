using ModuloCrypto.UI.Theme;
using System.ComponentModel;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.Windows.Forms;

namespace ModuloCrypto.UI.Controls;

public enum HologramState
{
    Idle,
    Encrypting,
    Locked,
    Decrypting,
    Unlocked
}

/// <summary>
/// Control GDI+ con doble búfer a 60 FPS que proyecta en perspectiva 3D un holograma binario
/// compuesto íntegramente por partículas '1' y '0' con transición fluida:
/// Cubo 3D (Reposo) -> Candado Cerrado (Cifrado) -> Candado Abierto (Descifrado).
/// </summary>
public sealed class HologramLockControl : Control
{
    private struct Vec3
    {
        public float X, Y, Z;
        public Vec3(float x, float y, float z) { X = x; Y = y; Z = z; }

        public static Vec3 Lerp(Vec3 a, Vec3 b, float t) =>
            new(a.X + (b.X - a.X) * t, a.Y + (b.Y - a.Y) * t, a.Z + (b.Z - a.Z) * t);
    }

    private sealed class BinaryParticle
    {
        public Vec3 CubePos;
        public Vec3 LockClosedPos;
        public Vec3 LockOpenPos;
        public bool IsShackle;
        public bool IsKeyhole;
        public bool IsAmbientSphere;
        public char BitChar;
        public float Phase;
        public float ColorMix; // 0 = Cyan, 1 = Violet
        public float OrbitRadius;
        public float OrbitSpeed;
    }

    private struct ProjectedPoint
    {
        public float ScreenX;
        public float ScreenY;
        public float Depth;
        public float Scale;
        public char BitChar;
        public Color Color;
        public bool IsKeyhole;
        public bool IsAmbient;
    }

    private readonly System.Windows.Forms.Timer _timer;
    private readonly List<BinaryParticle> _particles = new();
    private ProjectedPoint[] _projected = Array.Empty<ProjectedPoint>();
    private readonly Font[] _bitFonts;
    private readonly Font _hudBadgeFont = new("Cascadia Mono", 9.2f, FontStyle.Bold);
    private readonly Font _hudSubFont = new("Segoe UI Semibold", 8.5f);
    private readonly Random _rng = new(2026);

    private HologramState _state = HologramState.Idle;
    private float _angleY;
    private float _angleX = 0.24f;
    private float _ringAngle;
    private float _time;
    private float _morphToLock;     // 0 = Cube, 1 = Padlock
    private float _shackleOpen;     // 0 = Closed, 1 = Open
    private float _stateTimer;
    private float _pulseRadius;     // 0..1 expanding energy wave
    private float _pulseAlpha;
    private Color _pulseColor = HologramTheme.HologramCyan;
    private float _spinVelocity = 0.014f;
    private float _mouseParallaxX;
    private float _mouseParallaxY;

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public string ActiveAlgorithmLabel { get; set; } = "AESGCM";

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public string StatusSubtitle { get; set; } = "Núcleo Holográfico Listo";

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public bool ShowHud { get; set; } = true;

    public HologramState CurrentState => _state;

    public HologramLockControl()
    {
        DoubleBuffered = true;
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint |
                 ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        BackColor = HologramTheme.BackgroundBase;

        _bitFonts = new[]
        {
            new Font("Consolas", 7.2f, FontStyle.Bold),
            new Font("Consolas", 8.5f, FontStyle.Bold),
            new Font("Consolas", 9.8f, FontStyle.Bold),
            new Font("Consolas", 11.2f, FontStyle.Bold),
            new Font("Consolas", 12.6f, FontStyle.Bold),
            new Font("Consolas", 14.0f, FontStyle.Bold)
        };

        BuildGeometryParticles();
        _projected = new ProjectedPoint[_particles.Count];

        _timer = new System.Windows.Forms.Timer { Interval = 16 }; // ~60 FPS
        _timer.Tick += OnAnimationTick;
        _timer.Start();
    }

    public void SetIdle(string? subtitle = null)
    {
        _state = HologramState.Idle;
        _stateTimer = 0f;
        StatusSubtitle = subtitle ?? "Modo Reposo • Matriz Binaria 3D";
    }

    public void TriggerEncryptAnimation(string algorithmCode)
    {
        ActiveAlgorithmLabel = algorithmCode;
        _state = HologramState.Encrypting;
        _stateTimer = 0f;
        _spinVelocity = 0.14f;
        _pulseColor = HologramTheme.HologramCyan;
        _pulseRadius = 0.05f;
        _pulseAlpha = 1f;
        StatusSubtitle = $"Cifrando con {algorithmCode}...";
    }

    public void TriggerDecryptAnimation(string algorithmCode)
    {
        ActiveAlgorithmLabel = algorithmCode;
        _state = HologramState.Decrypting;
        _stateTimer = 0f;
        _morphToLock = Math.Max(_morphToLock, 0.75f);
        _spinVelocity = -0.13f;
        _pulseColor = HologramTheme.Success;
        _pulseRadius = 0.05f;
        _pulseAlpha = 1f;
        StatusSubtitle = $"Descifrando con {algorithmCode}...";
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        if (Width > 0 && Height > 0)
        {
            _mouseParallaxX = ((e.X / (float)Width) - 0.5f) * 0.35f;
            _mouseParallaxY = ((e.Y / (float)Height) - 0.5f) * 0.25f;
        }
    }

    protected override void OnMouseLeave(EventArgs e)
    {
        base.OnMouseLeave(e);
        _mouseParallaxX = 0f;
        _mouseParallaxY = 0f;
    }

    private void BuildGeometryParticles()
    {
        _particles.Clear();

        // 1. Construir geometría del Candado 3D (Cuerpo + Arco + Ojo de cerradura)
        var lockBodyPoints = new List<(Vec3 pos, bool isKeyhole)>();

        // 12 aristas y cuadrícula del cuerpo del candado: X [-0.66, 0.66], Y [-0.78, 0.12], Z [-0.26, 0.26]
        float bx = 0.66f, byMin = -0.78f, byMax = 0.12f, bz = 0.26f;

        // Cara frontal y trasera (matriz de bits)
        for (int ix = 0; ix <= 6; ix++)
        {
            float x = -bx + (2f * bx * ix / 6f);
            for (int iy = 0; iy <= 5; iy++)
            {
                float y = byMin + ((byMax - byMin) * iy / 5f);
                bool isEdge = ix == 0 || ix == 6 || iy == 0 || iy == 5;
                // Hueco del ojo de cerradura en el centro frontal
                bool inKeyhole = Math.Abs(x) < 0.15f && y > -0.52f && y < -0.15f;

                if (isEdge || (ix + iy) % 2 == 0)
                {
                    if (!inKeyhole)
                    {
                        lockBodyPoints.Add((new Vec3(x, y, bz), false));
                        lockBodyPoints.Add((new Vec3(x, y, -bz), false));
                    }
                }
            }
        }

        // Profundidad lateral (lados izquierdo, derecho, arriba, abajo del cuerpo)
        for (int iz = 1; iz <= 2; iz++)
        {
            float z = -bz + (2f * bz * iz / 3f);
            for (int iy = 0; iy <= 4; iy++)
            {
                float y = byMin + ((byMax - byMin) * iy / 4f);
                lockBodyPoints.Add((new Vec3(-bx, y, z), false));
                lockBodyPoints.Add((new Vec3(bx, y, z), false));
            }
            for (int ix = 1; ix <= 5; ix++)
            {
                float x = -bx + (2f * bx * ix / 6f);
                lockBodyPoints.Add((new Vec3(x, byMax, z), false));
                lockBodyPoints.Add((new Vec3(x, byMin, z), false));
            }
        }

        // Ojo de cerradura brillante en el centro frontal
        for (int a = 0; a < 10; a++)
        {
            float ang = a * (MathF.PI * 2f / 10f);
            lockBodyPoints.Add((new Vec3(MathF.Cos(ang) * 0.11f, -0.25f + MathF.Sin(ang) * 0.11f, bz + 0.03f), true));
        }
        for (int k = 0; k < 5; k++)
        {
            lockBodyPoints.Add((new Vec3(0f, -0.35f - k * 0.06f, bz + 0.03f), true));
        }

        // 2. Arco del candado (Shackle) en 3D
        var shacklePoints = new List<Vec3>();
        float shackleR = 0.42f;
        float archCenterY = 0.46f;

        // Dos capas de profundidad Z para dar volumen 3D real al arco
        foreach (float dz in new[] { -0.07f, 0.07f })
        {
            // Semicírculo superior (18 puntos)
            for (int i = 0; i <= 18; i++)
            {
                float t = i / 18f;
                float theta = MathF.PI * t; // 0 -> PI
                float x = MathF.Cos(theta) * shackleR;
                float y = archCenterY + MathF.Sin(theta) * shackleR;
                shacklePoints.Add(new Vec3(x, y, dz));
            }
            // Patas verticales izquierda y derecha
            for (int i = 1; i <= 5; i++)
            {
                float y = archCenterY - (i * 0.075f);
                shacklePoints.Add(new Vec3(-shackleR, y, dz));
                shacklePoints.Add(new Vec3(shackleR, y, dz));
            }
        }

        // 3. Construir puntos correspondientes del Cubo 3D (para morphing 1-a-1 sin saltos)
        int coreCount = lockBodyPoints.Count + shacklePoints.Count;
        var cubePoints = GenerateCubeLatticePoints(coreCount);

        int idx = 0;
        foreach (var (pos, isKeyhole) in lockBodyPoints)
        {
            _particles.Add(new BinaryParticle
            {
                CubePos = cubePoints[idx++],
                LockClosedPos = pos,
                LockOpenPos = pos,
                IsShackle = false,
                IsKeyhole = isKeyhole,
                BitChar = _rng.Next(2) == 0 ? '0' : '1',
                Phase = (float)(_rng.NextDouble() * Math.PI * 2),
                ColorMix = isKeyhole ? 0f : (float)_rng.NextDouble() * 0.55f
            });
        }

        // Pivote para abrir el arco: pata derecha (x = +shackleR, y = 0.46) levantada +0.30 y girada +36 grados
        float pivotX = shackleR;
        float pivotY = 0.14f;
        float openAngle = 0.62f; // ~35.5 grados
        float cosO = MathF.Cos(openAngle);
        float sinO = MathF.Sin(openAngle);

        foreach (var sp in shacklePoints)
        {
            // Levantar verticalmente + rotar alrededor de la pata derecha para un candado abierto inconfundible
            float raisedY = sp.Y + 0.30f;
            float rx = sp.X - pivotX;
            float ry = raisedY - (pivotY + 0.30f);
            float openX = pivotX + (rx * cosO - ry * sinO);
            float openY = (pivotY + 0.30f) + (rx * sinO + ry * cosO);

            _particles.Add(new BinaryParticle
            {
                CubePos = cubePoints[idx++],
                LockClosedPos = sp,
                LockOpenPos = new Vec3(openX, openY, sp.Z),
                IsShackle = true,
                IsKeyhole = false,
                BitChar = _rng.Next(2) == 0 ? '0' : '1',
                Phase = (float)(_rng.NextDouble() * Math.PI * 2),
                ColorMix = 0.15f + (float)_rng.NextDouble() * 0.35f
            });
        }

        // 4. Esfera exterior de partículas binarias orbitales (115 partículas)
        const int sphereCount = 115;
        float goldenAngle = MathF.PI * (3f - MathF.Sqrt(5f));
        for (int i = 0; i < sphereCount; i++)
        {
            float y = 1f - (i / (float)(sphereCount - 1)) * 2f;
            float rAtY = MathF.Sqrt(MathF.Max(0f, 1f - y * y));
            float theta = goldenAngle * i;
            float radius = 1.38f + (float)_rng.NextDouble() * 0.30f;

            var spherePos = new Vec3(MathF.Cos(theta) * rAtY * radius, y * radius, MathF.Sin(theta) * rAtY * radius);
            _particles.Add(new BinaryParticle
            {
                CubePos = spherePos,
                LockClosedPos = spherePos,
                LockOpenPos = spherePos,
                IsAmbientSphere = true,
                BitChar = _rng.Next(2) == 0 ? '0' : '1',
                Phase = (float)(_rng.NextDouble() * Math.PI * 2),
                ColorMix = 0.35f + (float)_rng.NextDouble() * 0.65f,
                OrbitRadius = radius,
                OrbitSpeed = 0.3f + (float)_rng.NextDouble() * 0.55f
            });
        }
    }

    private List<Vec3> GenerateCubeLatticePoints(int targetCount)
    {
        var pts = new List<Vec3>(targetCount);
        float s = 0.72f;

        // 12 aristas del cubo exterior (alta definición)
        Vec3[] v =
        {
            new(-s, -s, -s), new(s, -s, -s), new(s, s, -s), new(-s, s, -s),
            new(-s, -s,  s), new(s, -s,  s), new(s, s,  s), new(-s, s,  s)
        };
        int[,] edges =
        {
            {0,1},{1,2},{2,3},{3,0},
            {4,5},{5,6},{6,7},{7,4},
            {0,4},{1,5},{2,6},{3,7}
        };

        for (int e = 0; e < 12; e++)
        {
            for (int step = 0; step <= 8; step++)
            {
                float t = step / 8f;
                pts.Add(Vec3.Lerp(v[edges[e, 0]], v[edges[e, 1]], t));
            }
        }

        // Matriz interior + caras del cubo hasta igualar exactamente targetCount
        int grid = 5;
        for (int x = 0; x < grid && pts.Count < targetCount; x++)
        {
            for (int y = 0; y < grid && pts.Count < targetCount; y++)
            {
                for (int z = 0; z < grid && pts.Count < targetCount; z++)
                {
                    bool surface = x == 0 || x == grid - 1 || y == 0 || y == grid - 1 || z == 0 || z == grid - 1;
                    if (!surface && (x + y + z) % 2 != 0) continue;
                    float fx = -s + (2f * s * x / (grid - 1));
                    float fy = -s + (2f * s * y / (grid - 1));
                    float fz = -s + (2f * s * z / (grid - 1));
                    pts.Add(new Vec3(fx, fy, fz));
                }
            }
        }

        // Cubo núcleo interior (hipercubo) para completar puntos restantes
        float inner = 0.36f;
        while (pts.Count < targetCount)
        {
            int face = _rng.Next(6);
            float a = ((float)_rng.NextDouble() * 2f - 1f) * inner;
            float b = ((float)_rng.NextDouble() * 2f - 1f) * inner;
            Vec3 p = face switch
            {
                0 => new(inner, a, b),
                1 => new(-inner, a, b),
                2 => new(a, inner, b),
                3 => new(a, -inner, b),
                4 => new(a, b, inner),
                _ => new(a, b, -inner)
            };
            pts.Add(p);
        }

        return pts;
    }

    private void OnAnimationTick(object? sender, EventArgs e)
    {
        const float dt = 0.016f;
        _time += dt;
        _ringAngle += 0.018f;

        // Parpadeo sutil de bits '0' <-> '1'
        int flips = (_state == HologramState.Encrypting || _state == HologramState.Decrypting) ? 16 : 3;
        for (int i = 0; i < flips; i++)
        {
            int idx = _rng.Next(_particles.Count);
            _particles[idx].BitChar = _particles[idx].BitChar == '0' ? '1' : '0';
        }

        // Máquina de estados suave
        switch (_state)
        {
            case HologramState.Idle:
                _morphToLock = MoveTowards(_morphToLock, 0f, dt * 1.4f);
                _shackleOpen = MoveTowards(_shackleOpen, 0f, dt * 2.0f);
                _spinVelocity = Lerp(_spinVelocity, 0.014f, 0.06f);
                break;

            case HologramState.Encrypting:
                _stateTimer += dt;
                _morphToLock = MoveTowards(_morphToLock, 1f, dt * 1.35f);
                _shackleOpen = MoveTowards(_shackleOpen, 0f, dt * 2.5f);
                _spinVelocity = Lerp(_spinVelocity, 0.022f, 0.03f);
                if (_stateTimer >= 1.15f && _morphToLock >= 0.99f)
                {
                    _state = HologramState.Locked;
                    _pulseColor = HologramTheme.HologramCyan;
                    _pulseRadius = 0.08f;
                    _pulseAlpha = 1f;
                    StatusSubtitle = $"CIFRADO • LOCKED ({ActiveAlgorithmLabel})";
                }
                break;

            case HologramState.Locked:
                _morphToLock = MoveTowards(_morphToLock, 1f, dt * 2f);
                _shackleOpen = MoveTowards(_shackleOpen, 0f, dt * 2f);
                _spinVelocity = Lerp(_spinVelocity, 0.011f, 0.06f);
                break;

            case HologramState.Decrypting:
                _stateTimer += dt;
                _morphToLock = MoveTowards(_morphToLock, 1f, dt * 2.4f);
                _shackleOpen = MoveTowards(_shackleOpen, 1f, dt * 1.45f);
                _spinVelocity = Lerp(_spinVelocity, 0.014f, 0.035f);
                if (_stateTimer >= 1.1f && _shackleOpen >= 0.99f)
                {
                    _state = HologramState.Unlocked;
                    _pulseColor = HologramTheme.Success;
                    _pulseRadius = 0.08f;
                    _pulseAlpha = 1f;
                    StatusSubtitle = $"DESCIFRADO • UNLOCKED ({ActiveAlgorithmLabel})";
                }
                break;

            case HologramState.Unlocked:
                _morphToLock = 1f;
                _shackleOpen = MoveTowards(_shackleOpen, 1f, dt * 2f);
                _spinVelocity = Lerp(_spinVelocity, 0.012f, 0.06f);
                break;
        }

        _angleY += _spinVelocity;
        float targetAngleX = _state == HologramState.Idle
            ? 0.30f + MathF.Sin(_time * 0.7f) * 0.14f
            : 0.14f + MathF.Sin(_time * 0.9f) * 0.07f;
        _angleX = Lerp(_angleX, targetAngleX + _mouseParallaxY, 0.08f);

        if (_pulseAlpha > 0.01f)
        {
            _pulseRadius += dt * 1.25f;
            _pulseAlpha = MathF.Max(0f, _pulseAlpha - dt * 1.1f);
        }

        Invalidate();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = TextRenderingHint.AntiAliasGridFit;

        g.Clear(HologramTheme.BackgroundBase);

        if (Width < 40 || Height < 40) return;

        float cx = Width * 0.5f;
        float cy = Height * 0.45f;
        float minDim = MathF.Min(Width, Height);
        float scaleUnit = minDim * 0.255f;
        float baseY = cy + scaleUnit * 1.48f;

        // 1. Halo radial de fondo (luz holográfica violeta/cian)
        DrawAmbientBackdrop(g, cx, cy, minDim);

        // 2. Base circular holográfica + haz volumétrico ascendente
        DrawHologramProjectorBase(g, cx, cy, baseY, scaleUnit);

        // 3. Onda expansiva de pulso al cifrar / descifrar
        if (_pulseAlpha > 0.02f)
        {
            float pr = _pulseRadius * scaleUnit * 2.2f;
            int alpha = (int)(_pulseAlpha * 200);
            using var pulsePen = new Pen(Color.FromArgb(alpha, _pulseColor), 2.5f);
            g.DrawEllipse(pulsePen, cx - pr, cy - pr, pr * 2f, pr * 2f);

            float pr2 = pr * 0.72f;
            using var pulsePen2 = new Pen(Color.FromArgb(alpha / 2, HologramTheme.HologramViolet), 1.5f);
            g.DrawEllipse(pulsePen2, cx - pr2, cy - pr2, pr2 * 2f, pr2 * 2f);
        }

        // 4. Proyección 3D de todas las partículas '1' y '0'
        float morphEase = EaseInOutCubic(_morphToLock);
        float openEase = EaseInOutCubic(_shackleOpen);
        float hoverOffset = MathF.Sin(_time * 2.1f) * 0.055f;

        float rotY = _angleY + _mouseParallaxX;
        float cosY = MathF.Cos(rotY);
        float sinY = MathF.Sin(rotY);
        float cosX = MathF.Cos(_angleX);
        float sinX = MathF.Sin(_angleX);

        float sphereCosY = MathF.Cos(-_time * 0.28f);
        float sphereSinY = MathF.Sin(-_time * 0.28f);

        for (int i = 0; i < _particles.Count; i++)
        {
            var p = _particles[i];
            Vec3 pos;

            if (p.IsAmbientSphere)
            {
                // Órbita lenta en sentido contrario para contraste 3D
                float sx = p.CubePos.X * sphereCosY - p.CubePos.Z * sphereSinY;
                float sz = p.CubePos.X * sphereSinY + p.CubePos.Z * sphereCosY;
                float sy = p.CubePos.Y + MathF.Sin(_time * p.OrbitSpeed + p.Phase) * 0.07f;
                pos = new Vec3(sx, sy, sz);
            }
            else
            {
                Vec3 lockTarget = p.IsShackle
                    ? Vec3.Lerp(p.LockClosedPos, p.LockOpenPos, openEase)
                    : p.LockClosedPos;
                pos = Vec3.Lerp(p.CubePos, lockTarget, morphEase);

                // Efecto vórtice espiral durante la transición activa
                if (_state == HologramState.Encrypting || _state == HologramState.Decrypting)
                {
                    float swirl = MathF.Sin(morphEase * MathF.PI) * 0.45f;
                    float cs = MathF.Cos(swirl + pos.Y * 1.4f);
                    float sn = MathF.Sin(swirl + pos.Y * 1.4f);
                    pos = new Vec3(pos.X * cs - pos.Z * sn, pos.Y, pos.X * sn + pos.Z * cs);
                }

                pos.Y += hoverOffset;

                // Rotación 3D en Y y luego X
                float rx = pos.X * cosY - pos.Z * sinY;
                float rz = pos.X * sinY + pos.Z * cosY;
                float ry = pos.Y * cosX - rz * sinX;
                float rz2 = pos.Y * sinX + rz * cosX;
                pos = new Vec3(rx, ry, rz2);
            }

            // Proyección perspectiva
            float cameraDist = 4.3f;
            float perspective = cameraDist / (cameraDist - pos.Z);
            float screenX = cx + pos.X * scaleUnit * perspective;
            float screenY = cy - pos.Y * scaleUnit * perspective;

            // Color dinámico según estado y profundidad
            float depthNorm = Math.Clamp((pos.Z + 1.8f) / 3.6f, 0.1f, 1.0f);
            Color c = ComputeParticleColor(p, depthNorm);

            _projected[i] = new ProjectedPoint
            {
                ScreenX = screenX,
                ScreenY = screenY,
                Depth = pos.Z,
                Scale = perspective,
                BitChar = p.BitChar,
                Color = c,
                IsKeyhole = p.IsKeyhole,
                IsAmbient = p.IsAmbientSphere
            };
        }

        // Z-Sort (Painter's algorithm: de atrás hacia adelante)
        Array.Sort(_projected, static (a, b) => a.Depth.CompareTo(b.Depth));

        // 5. Renderizado de cada '1' y '0' con brillo holográfico
        for (int i = 0; i < _projected.Length; i++)
        {
            var pt = _projected[i];
            int fontIdx = pt.IsAmbient
                ? Math.Clamp((int)((pt.Scale - 0.65f) * 3.5f), 0, 2)
                : Math.Clamp((int)((pt.Scale - 0.65f) * 6.5f), 1, _bitFonts.Length - 1);

            Font f = _bitFonts[fontIdx];
            string ch = pt.BitChar == '1' ? "1" : "0";

            if (!pt.IsAmbient && pt.Depth > 0.15f)
            {
                // Resplandor suave detrás de los bits del frente
                using var glowBrush = new SolidBrush(Color.FromArgb(pt.Color.A / 4, pt.Color.R, pt.Color.G, pt.Color.B));
                g.FillEllipse(glowBrush, pt.ScreenX - 6f, pt.ScreenY - 6f, 12f, 12f);
            }

            using var textBrush = new SolidBrush(pt.Color);
            g.DrawString(ch, f, textBrush, pt.ScreenX - 5f, pt.ScreenY - 7f);
        }

        // 6. HUD Superior / Inferior del Holograma
        if (ShowHud)
        {
            DrawHologramHud(g);
        }
    }

    private void DrawAmbientBackdrop(Graphics g, float cx, float cy, float minDim)
    {
        float r = minDim * 0.44f;
        var rect = new RectangleF(cx - r, cy - r, r * 2f, r * 2f);
        using var path = new GraphicsPath();
        path.AddEllipse(rect);
        using var pgb = new PathGradientBrush(path);

        Color centerCol = _state switch
        {
            HologramState.Unlocked => Color.FromArgb(48, HologramTheme.Success),
            HologramState.Locked => Color.FromArgb(55, HologramTheme.HologramCyan),
            _ => Color.FromArgb(52, HologramTheme.AccentStart)
        };
        pgb.CenterColor = centerCol;
        pgb.SurroundColors = new[] { Color.FromArgb(0, HologramTheme.BackgroundBase) };
        g.FillEllipse(pgb, rect);
    }

    private void DrawHologramProjectorBase(Graphics g, float cx, float cy, float baseY, float scaleUnit)
    {
        float rx = scaleUnit * 1.42f;
        float ry = scaleUnit * 0.34f;

        // Haz de luz cónico ascendente
        PointF[] cone =
        {
            new(cx - rx * 0.78f, baseY),
            new(cx + rx * 0.78f, baseY),
            new(cx + rx * 1.15f, cy - scaleUnit * 1.05f),
            new(cx - rx * 1.15f, cy - scaleUnit * 1.05f)
        };
        Color beamColor = _state == HologramState.Unlocked ? HologramTheme.Success : HologramTheme.HologramCyan;
        using (var beamBrush = new LinearGradientBrush(
            new PointF(cx, baseY),
            new PointF(cx, cy - scaleUnit),
            Color.FromArgb(42, beamColor),
            Color.FromArgb(0, HologramTheme.AccentStart)))
        {
            g.FillPolygon(beamBrush, cone);
        }

        // Anillos concéntricos luminosos en perspectiva
        for (int ring = 0; ring < 3; ring++)
        {
            float factor = 1.0f - ring * 0.24f;
            float w = rx * 2f * factor;
            float h = ry * 2f * factor;
            var rRect = new RectangleF(cx - w / 2f, baseY - h / 2f, w, h);

            Color ringCol = ring == 1 ? HologramTheme.HologramViolet : beamColor;
            int alpha = 180 - ring * 35;

            using var glowPen = new Pen(Color.FromArgb(alpha / 3, ringCol), 5f);
            g.DrawEllipse(glowPen, rRect);

            using var corePen = new Pen(Color.FromArgb(alpha, ringCol), 1.5f);
            g.DrawEllipse(corePen, rRect);

            // Arcos giratorios tipo HUD
            float startDeg = (_ringAngle * (ring % 2 == 0 ? 45f : -60f) + ring * 110f) % 360f;
            using var arcPen = new Pen(Color.FromArgb(230, HologramTheme.TextPrimary), 2f);
            g.DrawArc(arcPen, rRect, startDeg, 36f);
            g.DrawArc(arcPen, rRect, startDeg + 180f, 36f);
        }

        // Núcleo central del proyector
        using var centerGlow = new SolidBrush(Color.FromArgb(90, beamColor));
        g.FillEllipse(centerGlow, cx - rx * 0.28f, baseY - ry * 0.28f, rx * 0.56f, ry * 0.56f);
    }

    private void DrawHologramHud(Graphics g)
    {
        // Etiqueta superior izquierda: Estado del Holograma (medida dinámicamente sin encimarse)
        string stateTag = _state switch
        {
            HologramState.Idle => "● IDLE • CUBO BINARIO 3D",
            HologramState.Encrypting => "● ENCRYPTING • CONVERGIENDO...",
            HologramState.Locked => "● LOCKED • CANDADO CERRADO",
            HologramState.Decrypting => "● DECRYPTING • ABRIENDO ARCO...",
            HologramState.Unlocked => "● UNLOCKED • CANDADO ABIERTO",
            _ => "● HOLOGRAMA"
        };

        Color tagColor = _state switch
        {
            HologramState.Unlocked => HologramTheme.Success,
            HologramState.Locked => HologramTheme.HologramCyan,
            HologramState.Encrypting => HologramTheme.AccentGlow,
            HologramState.Decrypting => HologramTheme.HologramCyan,
            _ => HologramTheme.HologramViolet
        };

        Size stateMeasured = TextRenderer.MeasureText(g, stateTag, _hudBadgeFont, Size.Empty, TextFormatFlags.SingleLine | TextFormatFlags.NoPrefix);
        int stateW = Math.Clamp(stateMeasured.Width + 24, 160, Math.Max(180, Width - 32));
        var badgeRect = new Rectangle(16, 14, stateW, 30);

        using (var path = HologramTheme.CreateRoundedPath(badgeRect, 14))
        using (var bg = new SolidBrush(Color.FromArgb(190, 21, 18, 38)))
        using (var border = new Pen(Color.FromArgb(150, tagColor), 1f))
        {
            g.FillPath(bg, path);
            g.DrawPath(border, path);
        }
        TextRenderer.DrawText(g, stateTag, _hudBadgeFont, badgeRect, tagColor,
            TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);

        // Etiqueta superior derecha: Algoritmo activo (se apila debajo si el panel es estrecho)
        string algText = $"ALG: {ActiveAlgorithmLabel}";
        Size algMeasured = TextRenderer.MeasureText(g, algText, _hudBadgeFont, Size.Empty, TextFormatFlags.SingleLine | TextFormatFlags.NoPrefix);
        int algW = Math.Max(130, algMeasured.Width + 24);
        var algRect = new Rectangle(Width - algW - 16, 14, algW, 30);

        if (badgeRect.Right + 10 > algRect.Left)
        {
            algRect = new Rectangle(16, 50, Math.Min(algW, Math.Max(130, Width - 32)), 30);
        }

        using (var path = HologramTheme.CreateRoundedPath(algRect, 14))
        using (var bg = new SolidBrush(Color.FromArgb(190, 21, 18, 38)))
        using (var border = new Pen(Color.FromArgb(140, HologramTheme.AccentGlow), 1f))
        {
            g.FillPath(bg, path);
            g.DrawPath(border, path);
        }
        TextRenderer.DrawText(g, algText, _hudBadgeFont, algRect, HologramTheme.HologramCyan,
            TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);

        // Subtítulo inferior centrado con EndEllipsis
        var subRect = new Rectangle(16, Height - 32, Math.Max(40, Width - 32), 24);
        TextRenderer.DrawText(g, StatusSubtitle, _hudSubFont, subRect, HologramTheme.TextSecondary,
            TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
    }

    private Color ComputeParticleColor(BinaryParticle p, float depthNorm)
    {
        if (p.IsAmbientSphere)
        {
            int a = (int)(35 + depthNorm * 95);
            return BlendColor(HologramTheme.HologramCyan, HologramTheme.HologramViolet, p.ColorMix, a);
        }

        int alpha = (int)(90 + depthNorm * 165);

        if (p.IsKeyhole)
            return Color.FromArgb(Math.Min(255, alpha + 30), 220, 250, 255);

        if (_state == HologramState.Unlocked || _state == HologramState.Decrypting)
        {
            Color target = p.IsShackle ? HologramTheme.Success : HologramTheme.HologramCyan;
            return BlendColor(target, HologramTheme.HologramViolet, p.ColorMix * 0.45f, alpha);
        }

        if (_state == HologramState.Locked || _state == HologramState.Encrypting)
        {
            Color target = p.IsShackle ? HologramTheme.HologramCyan : HologramTheme.HologramViolet;
            return BlendColor(target, HologramTheme.HologramCyan, 1f - p.ColorMix * 0.7f, alpha);
        }

        // Idle cube: eléctrico azul cian + violeta neón
        return BlendColor(HologramTheme.HologramCyan, HologramTheme.HologramViolet, p.ColorMix, alpha);
    }

    private static Color BlendColor(Color a, Color b, float t, int alpha)
    {
        t = Math.Clamp(t, 0f, 1f);
        int r = (int)(a.R + (b.R - a.R) * t);
        int g = (int)(a.G + (b.G - a.G) * t);
        int bl = (int)(a.B + (b.B - a.B) * t);
        return Color.FromArgb(Math.Clamp(alpha, 0, 255), r, g, bl);
    }

    private static float Lerp(float a, float b, float t) => a + (b - a) * t;

    private static float MoveTowards(float current, float target, float maxDelta)
    {
        if (MathF.Abs(target - current) <= maxDelta) return target;
        return current + MathF.Sign(target - current) * maxDelta;
    }

    private static float EaseInOutCubic(float x)
    {
        x = Math.Clamp(x, 0f, 1f);
        return x < 0.5f ? 4f * x * x * x : 1f - MathF.Pow(-2f * x + 2f, 3f) / 2f;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _timer.Stop();
            _timer.Dispose();
            foreach (var f in _bitFonts) f.Dispose();
            _hudBadgeFont.Dispose();
            _hudSubFont.Dispose();
        }
        base.Dispose(disposing);
    }
}
