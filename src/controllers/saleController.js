import Appointment from '../models/appointment.js';
import BarberoModel from '../models/barbero.js';
import { pool } from '../config/database.js';
import Sale from '../models/sale.js';
import Servicio from '../models/servicios.js';
import User from '../models/user.js';

const ALLOWED_PAYMENT_METHODS = ['efectivo', 'transferencia', 'tarjeta'];
const PAYMENT_METHOD_LABELS = {
  efectivo: ['efectivo', 'cash'],
  transferencia: ['transferencia', 'transferencia bancaria'],
  tarjeta: ['tarjeta', 'tarjeta de credito', 'tarjeta de debito'],
};
const COMPLETED_ESTADO_ID = 3;
const CANCELLED_ESTADO_ID = 4;
const NO_SHOW_ESTADO_ID = 5;
const APPOINTMENT_BREAK_MINUTES = 10;

const pad2 = (value) => String(value).padStart(2, '0');

const formatLocalDate = (date) => {
  return `${date.getFullYear()}-${pad2(date.getMonth() + 1)}-${pad2(date.getDate())}`;
};

const formatLocalTimestamp = (date) => {
  return `${formatLocalDate(date)} ${pad2(date.getHours())}:${pad2(date.getMinutes())}:${pad2(date.getSeconds())}`;
};

const parseDateValue = (value) => {
  if (!value) return null;

  if (typeof value === 'string') {
    const trimmed = value.trim();
    const datePrefixPattern = /^(\d{4}-\d{2}-\d{2})(T.*)?$/;
    const match = trimmed.match(datePrefixPattern);

    if (match) {
      const [year, month, day] = match[1].split('-').map((num) => Number.parseInt(num, 10));
      const parsedLocalDate = new Date(year, month - 1, day);
      if (Number.isNaN(parsedLocalDate.getTime())) {
        return null;
      }
      return parsedLocalDate;
    }
  }

  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return null;
  }
  return parsed;
};

const getDayRange = (fecha) => {
  const start = new Date(fecha);
  start.setHours(0, 0, 0, 0);

  const end = new Date(start);
  end.setDate(end.getDate() + 1);

  return {
    start,
    end,
    startSql: formatLocalTimestamp(start),
    endSql: formatLocalTimestamp(end),
    dayLabel: formatLocalDate(start),
  };
};

const parsePositiveInt = (value) => {
  const parsed = Number.parseInt(value, 10);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : null;
};

const parseDateKey = (value) => {
  if (typeof value !== 'string') return null;

  const match = value.trim().match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!match) return null;

  const [, yearText, monthText, dayText] = match;
  const year = Number.parseInt(yearText, 10);
  const month = Number.parseInt(monthText, 10);
  const day = Number.parseInt(dayText, 10);
  const date = new Date(year, month - 1, day);

  if (
    Number.isNaN(date.getTime()) ||
    date.getFullYear() !== year ||
    date.getMonth() !== month - 1 ||
    date.getDate() !== day
  ) {
    return null;
  }

  return `${yearText}-${monthText}-${dayText}`;
};

const parseTimeValue = (value) => {
  if (typeof value !== 'string') return null;

  const match = value.trim().match(/^(\d{2}):(\d{2})(?::\d{2})?$/);
  if (!match) return null;

  const hour = Number.parseInt(match[1], 10);
  const minute = Number.parseInt(match[2], 10);
  if (hour < 0 || hour > 23 || minute < 0 || minute > 59) return null;

  return `${pad2(hour)}:${pad2(minute)}`;
};

const addMinutesToTime = (time, minutes) => {
  const [hour, minute] = time.split(':').map((part) => Number.parseInt(part, 10));
  const totalMinutes = hour * 60 + minute + minutes;

  if (totalMinutes <= 0 || totalMinutes > 24 * 60) return null;

  return `${pad2(Math.floor(totalMinutes / 60))}:${pad2(totalMinutes % 60)}`;
};

const normalizeOptionalText = (value) => {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed || null;
};

const createWalkInClient = async ({ clienteNombre, clienteTelefono }) => {
  const nombre = normalizeOptionalText(clienteNombre) || 'Cliente mostrador';
  const telefono = normalizeOptionalText(clienteTelefono);
  const email = `mostrador.${Date.now()}.${Math.random().toString(36).slice(2, 8)}@barberia-carlyn.local`;

  return User.create({
    nombre,
    email,
    telefono,
    password: 'MOSTRADOR_SIN_LOGIN',
    idRol: 3,
  });
};

const findPaymentMethodId = async (paymentMethod) => {
  const labels = PAYMENT_METHOD_LABELS[paymentMethod] || [paymentMethod];
  const result = await pool.query(
    `
      SELECT id
      FROM metodos_pago
      WHERE LOWER(nombre) = ANY($1)
      ORDER BY id
      LIMIT 1
    `,
    [labels]
  );

  return result.rows[0]?.id || null;
};

export const registerSale = async (req, res, next) => {
  try {
    const { items, metodoPago, clienteNombre, notas } = req.body;

    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ message: 'La venta debe incluir al menos un producto' });
    }

    const paymentMethod = (metodoPago || 'efectivo').toString().toLowerCase();
    if (!ALLOWED_PAYMENT_METHODS.includes(paymentMethod)) {
      return res.status(400).json({
        message: 'Metodo de pago invalido. Usa efectivo, transferencia o tarjeta',
      });
    }

    for (const item of items) {
      const productoId = Number.parseInt(item.productoId, 10);
      const cantidad = Number.parseInt(item.cantidad, 10);

      if (Number.isNaN(productoId) || productoId <= 0) {
        return res.status(400).json({ message: 'productoId invalido en detalle' });
      }

      if (Number.isNaN(cantidad) || cantidad <= 0) {
        return res.status(400).json({ message: 'cantidad invalida en detalle' });
      }
    }

    const sale = await Sale.create({
      items,
      metodoPago: paymentMethod,
      clienteNombre: typeof clienteNombre === 'string' ? clienteNombre.trim() : null,
      notas: typeof notas === 'string' ? notas.trim() : null,
      vendidaPor: req.user.id,
    });

    res.status(201).json({
      message: 'Venta registrada correctamente',
      data: sale,
    });
  } catch (error) {
    if (error.statusCode) {
      return res.status(error.statusCode).json({ message: error.message });
    }

    next(error);
  }
};

export const registerWalkInService = async (req, res, next) => {
  try {
    const {
      localId,
      barberoId,
      servicioId,
      fecha,
      horaInicio,
      metodoPago = 'efectivo',
      clienteNombre,
      clienteTelefono,
      notas,
    } = req.body;

    const parsedLocalId = parsePositiveInt(localId);
    const parsedBarberoId = parsePositiveInt(barberoId);
    const parsedServicioId = parsePositiveInt(servicioId);
    const parsedFecha = parseDateKey(fecha);
    const parsedHoraInicio = parseTimeValue(horaInicio);
    const paymentMethod = String(metodoPago || '').toLowerCase();

    if (!parsedLocalId || !parsedBarberoId || !parsedServicioId || !parsedFecha || !parsedHoraInicio) {
      return res.status(400).json({
        message: 'Sucursal, barbero, servicio, fecha y hora son obligatorios.',
      });
    }

    if (!ALLOWED_PAYMENT_METHODS.includes(paymentMethod)) {
      return res.status(400).json({ message: 'Metodo de pago no valido.' });
    }

    const [servicio, barbero] = await Promise.all([
      Servicio.findById(parsedServicioId),
      BarberoModel.getById(parsedBarberoId),
    ]);

    if (!servicio || servicio.activo === false) {
      return res.status(404).json({ message: 'El servicio seleccionado no existe o no esta activo.' });
    }

    if (!barbero || barbero.activo === false) {
      return res.status(404).json({ message: 'El barbero seleccionado no existe o no esta activo.' });
    }

    if (Number(barbero.local_id) !== parsedLocalId) {
      return res.status(400).json({ message: 'El barbero no pertenece a la sucursal seleccionada.' });
    }

    const duracion = parsePositiveInt(servicio.duracion) || 30;
    const horaFin = addMinutesToTime(parsedHoraInicio, duracion);
    if (!horaFin) {
      return res.status(400).json({
        message: 'La hora seleccionada no permite completar la duracion del servicio.',
      });
    }

    const conflict = await Appointment.hasConflict({
      barberoId: parsedBarberoId,
      fecha: parsedFecha,
      horaInicio: parsedHoraInicio,
      horaFin,
      breakMinutes: APPOINTMENT_BREAK_MINUTES,
      cancelledEstadoIds: [CANCELLED_ESTADO_ID, NO_SHOW_ESTADO_ID],
    });

    if (conflict) {
      return res.status(409).json({
        message: 'Ese horario ya esta ocupado para el barbero seleccionado.',
      });
    }

    const cliente = await createWalkInClient({ clienteNombre, clienteTelefono });
    const metodoPagoId = await findPaymentMethodId(paymentMethod);
    const montoPagado = Number.parseFloat(servicio.precio || 0);
    const notaPartes = [
      'Servicio registrado en mostrador.',
      `Pago: ${paymentMethod}.`,
      normalizeOptionalText(notas),
    ].filter(Boolean);

    const cita = await Appointment.create({
      clienteId: cliente.id,
      barberoId: parsedBarberoId,
      servicioId: parsedServicioId,
      localId: parsedLocalId,
      fecha: parsedFecha,
      horaInicio: parsedHoraInicio,
      horaFin,
      estadoId: COMPLETED_ESTADO_ID,
      notas: notaPartes.join(' '),
      metodoPagoId,
      montoPagado,
      recordatorioEnviado: false,
    });

    return res.status(201).json({
      message: 'Servicio de mostrador registrado correctamente.',
      data: cita,
    });
  } catch (error) {
    next(error);
  }
};

export const getSalesHistoryByDay = async (req, res, next) => {
  try {
    const selectedDate = req.query.fecha ? parseDateValue(req.query.fecha) : new Date();
    if (!selectedDate) {
      return res.status(400).json({ message: 'fecha invalida. Usa formato YYYY-MM-DD' });
    }

    const range = getDayRange(selectedDate);
    const sales = await Sale.getHistoryByDay(range.dayLabel);

    const totalVentasDia = sales.reduce((acc, sale) => acc + Number.parseFloat(sale.total || 0), 0);

    res.json({
      message: 'Historial de ventas obtenido correctamente',
      date: range.dayLabel,
      totalTransacciones: sales.length,
      totalVentasDia: Number.parseFloat(totalVentasDia.toFixed(2)),
      data: sales,
    });
  } catch (error) {
    next(error);
  }
};

export const generateCashCut = async (req, res, next) => {
  try {
    const selectedDate = req.body.fecha ? parseDateValue(req.body.fecha) : new Date();
    if (!selectedDate) {
      return res.status(400).json({ message: 'fecha invalida. Usa formato YYYY-MM-DD' });
    }

    const range = getDayRange(selectedDate);

    const cashCut = await Sale.createCashCut({
      from: range.startSql,
      to: range.endSql,
      generadoPor: req.user.id,
    });

    res.status(201).json({
      message: 'Corte de caja generado correctamente',
      data: cashCut,
    });
  } catch (error) {
    next(error);
  }
};
